import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const IV_LENGTH = 16;
const MAC_LENGTH = 32;
const LOCAL_BACKUP_METADATA_INFO = Buffer.from('20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY');
const BACKUP_KEY_INFO = Buffer.from('20240801_SIGNAL_BACKUP_KEY');
const MESSAGE_BACKUP_INFO = Buffer.from('20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:');

const FRAME_KIND = new Map([
  [1, 'account'],
  [2, 'recipient'],
  [3, 'chat'],
  [4, 'chatItem'],
  [5, 'stickerPack'],
  [6, 'adHocCall'],
  [7, 'notificationProfile'],
  [8, 'chatFolder'],
]);

function usage() {
  console.error(`Usage:
  node backup-v2-raw.mjs summary <snapshotDir> <passphraseFile>
  node backup-v2-raw.mjs check-files <snapshotDir>
  node backup-v2-raw.mjs check-refs <snapshotDir> <passphraseFile>
  node backup-v2-raw.mjs check-media-refs <snapshotDir> <passphraseFile>
  node backup-v2-raw.mjs official-validate <snapshotDir> <passphraseFile> [nativeLibsignalNodePath]
  node backup-v2-raw.mjs merge <oldSnapshotDir> <oldPassphraseFile> <newSnapshotDir> <newPassphraseFile> <outBaseDir>`);
  process.exit(2);
}

function normalizePassphrase(text) {
  return text
    .trim()
    .replace(/#/g, 'o')
    .replace(/=/g, '0')
    .replace(/[^a-zA-Z0-9]/g, '')
    .toLowerCase();
}

async function readPassphrase(path) {
  const passphrase = normalizePassphrase(await readFile(path, 'utf8'));
  if (!/^[a-z0-9]{64}$/.test(passphrase)) {
    throw new Error(`Invalid normalized passphrase length for ${path}: ${passphrase.length}`);
  }
  return passphrase;
}

function hkdf(info, ikm, length, salt = Buffer.alloc(0)) {
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
}

function deriveBackupKey(passphrase) {
  return hkdf(BACKUP_KEY_INFO, Buffer.from(passphrase, 'ascii'), 32);
}

function deriveMetadataKey(backupKey) {
  return hkdf(LOCAL_BACKUP_METADATA_INFO, backupKey, 32);
}

function deriveMessageKeys(backupKey, backupId) {
  const material = hkdf(Buffer.concat([MESSAGE_BACKUP_INFO, backupId]), backupKey, 64);
  return { hmacKey: material.subarray(0, 32), aesKey: material.subarray(32, 64) };
}

function readVarint(buffer, offset) {
  let value = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < buffer.length) {
    const byte = buffer[pos++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, offset: pos };
    shift += 7n;
    if (shift > 70n) throw new Error('Invalid varint');
  }
  throw new Error('Truncated varint');
}

function writeVarint(value) {
  let v = BigInt(value);
  const out = [];
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
  return Buffer.from(out);
}

function parseMessage(buffer) {
  const fields = [];
  let offset = 0;
  while (offset < buffer.length) {
    const tag = readVarint(buffer, offset);
    offset = tag.offset;
    const field = Number(tag.value >> 3n);
    const wire = Number(tag.value & 7n);
    let value;
    if (wire === 0) {
      const read = readVarint(buffer, offset);
      offset = read.offset;
      value = read.value;
    } else if (wire === 1) {
      value = buffer.subarray(offset, offset + 8);
      offset += 8;
    } else if (wire === 2) {
      const len = readVarint(buffer, offset);
      offset = len.offset;
      const end = offset + Number(len.value);
      value = buffer.subarray(offset, end);
      offset = end;
    } else if (wire === 5) {
      value = buffer.subarray(offset, offset + 4);
      offset += 4;
    } else {
      throw new Error(`Unsupported protobuf wire type ${wire}`);
    }
    fields.push({ field, wire, value });
  }
  return fields;
}

function encodeMessage(fields) {
  const chunks = [];
  for (const item of fields) {
    chunks.push(writeVarint((BigInt(item.field) << 3n) | BigInt(item.wire)));
    if (item.wire === 0) {
      chunks.push(writeVarint(item.value));
    } else if (item.wire === 1 || item.wire === 5) {
      chunks.push(Buffer.from(item.value));
    } else if (item.wire === 2) {
      chunks.push(writeVarint(item.value.length), Buffer.from(item.value));
    }
  }
  return Buffer.concat(chunks);
}

function decodeDelimited(buffer) {
  const records = [];
  let offset = 0;
  while (offset < buffer.length) {
    const len = readVarint(buffer, offset);
    offset = len.offset;
    const end = offset + Number(len.value);
    if (end > buffer.length) throw new Error('Truncated delimited record');
    records.push(buffer.subarray(offset, end));
    offset = end;
  }
  return records;
}

function encodeDelimited(records) {
  const chunks = [];
  for (const record of records) {
    chunks.push(writeVarint(record.length), record);
  }
  return Buffer.concat(chunks);
}

function getLengthField(message, fieldNo) {
  return parseMessage(message).find(field => field.field === fieldNo && field.wire === 2)?.value;
}

function decryptBackupId(passphrase, metadataBytes) {
  const backupKey = deriveBackupKey(passphrase);
  const metadata = parseMessage(metadataBytes);
  const backupIdMessage = metadata.find(field => field.field === 2 && field.wire === 2)?.value;
  if (!backupIdMessage) throw new Error('metadata missing backupId');
  const backupIdFields = parseMessage(backupIdMessage);
  const iv = backupIdFields.find(field => field.field === 1 && field.wire === 2)?.value;
  const encryptedId = backupIdFields.find(field => field.field === 2 && field.wire === 2)?.value;
  if (!iv || !encryptedId) throw new Error('metadata missing encrypted backup id fields');
  const decipher = createDecipheriv(
    'aes-256-ctr',
    deriveMetadataKey(backupKey),
    Buffer.concat([iv, Buffer.alloc(4)])
  );
  return { backupKey, backupId: Buffer.concat([decipher.update(encryptedId), decipher.final()]) };
}

async function readSnapshot(snapshotDir, passphraseFile) {
  const passphrase = await readPassphrase(passphraseFile);
  const metadata = await readFile(join(snapshotDir, 'metadata'));
  const { backupKey, backupId } = decryptBackupId(passphrase, metadata);
  const { hmacKey, aesKey } = deriveMessageKeys(backupKey, backupId);
  const main = await readFile(join(snapshotDir, 'main'));
  const body = main.subarray(0, -MAC_LENGTH);
  const mac = main.subarray(-MAC_LENGTH);
  const expectedMac = createHmac('sha256', hmacKey).update(body).digest();
  if (!expectedMac.equals(mac)) throw new Error(`Bad main MAC for ${snapshotDir}`);
  const iv = body.subarray(0, IV_LENGTH);
  const encrypted = body.subarray(IV_LENGTH);
  const decipher = createDecipheriv('aes-256-cbc', aesKey, iv);
  const compressed = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  const plain = gunzipSync(compressed);
  const records = decodeDelimited(plain);
  const files = decodeFilesList(await readFile(join(snapshotDir, 'files')));
  return { snapshotDir, metadata, backupId, records, files };
}

function frameKind(frameRecord) {
  const fields = parseMessage(frameRecord);
  const oneof = fields.find(field => FRAME_KIND.has(field.field) && field.wire === 2);
  return oneof ? FRAME_KIND.get(oneof.field) : 'unknown';
}

function framePayload(frameRecord) {
  return parseMessage(frameRecord).find(field => FRAME_KIND.has(field.field) && field.wire === 2);
}

function wrapFrame(fieldNo, payload) {
  return encodeMessage([{ field: fieldNo, wire: 2, value: payload }]);
}

function rewriteNested(buffer, callback) {
  return encodeMessage(callback(parseMessage(buffer)));
}

function add(value, offset) {
  if (typeof offset === 'object') {
    const mapped = offset.map?.get(BigInt(value).toString());
    if (mapped != null) return mapped;
    return BigInt(value) + offset.offset;
  }
  return BigInt(value) + offset;
}

function offsetVarintFields(fields, fieldNos, offset) {
  for (const field of fields) {
    if (field.wire === 0 && fieldNos.includes(field.field)) {
      field.value = add(field.value, offset);
    }
  }
}

function offsetNestedFields(fields, fieldNos, offset, nestedCallback) {
  for (const field of fields) {
    if (field.wire === 2 && fieldNos.includes(field.field)) {
      field.value = rewriteNested(field.value, nestedCallback || (nested => {
        offsetVarintFields(nested, [1, 2], offset);
        return nested;
      }));
    }
  }
}

function offsetRecipient(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [1], offsets.recipient);
    offsetNestedFields(fields, [4], offsets.recipient, distributionItem => {
      offsetNestedFields(distributionItem, [3], offsets.recipient, list => {
        offsetVarintFields(list, [4], offsets.recipient);
        return list;
      });
      return distributionItem;
    });
    return fields;
  });
}

function offsetChat(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [1], offsets.chat);
    offsetVarintFields(fields, [2], offsets.recipient);
    return fields;
  });
}

function offsetSendStatus(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [1], offsets.recipient);
    return fields;
  });
}

function offsetReactions(fields, fieldNo, offsets) {
  offsetNestedFields(fields, [fieldNo], offsets.recipient, reaction => {
    offsetVarintFields(reaction, [2], offsets.recipient);
    return reaction;
  });
}

function offsetStandardMessage(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], offsets.recipient, quote => {
      offsetVarintFields(quote, [2], offsets.recipient);
      return quote;
    });
    offsetReactions(fields, 6, offsets);
    return fields;
  });
}

function offsetPoll(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [3], offsets.recipient, option => {
      offsetNestedFields(option, [2], offsets.recipient, vote => {
        offsetVarintFields(vote, [1], offsets.recipient);
        return vote;
      });
      return option;
    });
    offsetReactions(fields, 5, offsets);
    return fields;
  });
}

function offsetChatUpdate(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [7], offsets.call, individualCall => {
      offsetVarintFields(individualCall, [1], offsets.call);
      return individualCall;
    });
    offsetNestedFields(fields, [8], offsets.call, groupCall => {
      offsetVarintFields(groupCall, [1], offsets.call);
      offsetVarintFields(groupCall, [3, 4], offsets.recipient);
      return groupCall;
    });
    offsetNestedFields(fields, [11], offsets.recipient, pinMessage => {
      offsetVarintFields(pinMessage, [2], offsets.recipient);
      return pinMessage;
    });
    return fields;
  });
}

function offsetChatItem(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [1], offsets.chat);
    offsetVarintFields(fields, [2], offsets.recipient);
    offsetNestedFields(fields, [6], 0n, revision => parseMessage(offsetChatItem(encodeMessage(revision), offsets)));
    offsetNestedFields(fields, [9], offsets.recipient, outgoing => {
      offsetNestedFields(outgoing, [1], offsets.recipient, status => parseMessage(offsetSendStatus(encodeMessage(status), offsets)));
      return outgoing;
    });
    offsetNestedFields(fields, [11], offsets.recipient, standard => parseMessage(offsetStandardMessage(encodeMessage(standard), offsets)));
    offsetNestedFields(fields, [12], offsets.recipient, contact => {
      offsetReactions(contact, 2, offsets);
      return contact;
    });
    offsetNestedFields(fields, [13], offsets.recipient, sticker => {
      offsetReactions(sticker, 2, offsets);
      return sticker;
    });
    offsetNestedFields(fields, [15], offsets.recipient, update => parseMessage(offsetChatUpdate(encodeMessage(update), offsets)));
    offsetNestedFields(fields, [18], offsets.recipient, viewOnce => {
      offsetReactions(viewOnce, 2, offsets);
      return viewOnce;
    });
    offsetNestedFields(fields, [19], offsets.recipient, storyReply => {
      offsetReactions(storyReply, 3, offsets);
      return storyReply;
    });
    offsetNestedFields(fields, [20], offsets.recipient, poll => parseMessage(offsetPoll(encodeMessage(poll), offsets)));
    offsetNestedFields(fields, [22], offsets.recipient, adminDeleted => {
      offsetVarintFields(adminDeleted, [1], offsets.recipient);
      return adminDeleted;
    });
    return fields;
  });
}

function offsetAdHocCall(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [1], offsets.call);
    offsetVarintFields(fields, [2], offsets.recipient);
    return fields;
  });
}

function offsetNotificationProfile(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [7], offsets.recipient);
    return fields;
  });
}

function offsetChatFolder(payload, offsets) {
  return rewriteNested(payload, fields => {
    offsetVarintFields(fields, [7, 8], offsets.recipient);
    return fields;
  });
}

function offsetFrame(frameRecord, offsets) {
  const payload = framePayload(frameRecord);
  if (!payload) return frameRecord;
  switch (payload.field) {
    case 2:
      return wrapFrame(2, offsetRecipient(payload.value, offsets));
    case 3:
      return wrapFrame(3, offsetChat(payload.value, offsets));
    case 4:
      return wrapFrame(4, offsetChatItem(payload.value, offsets));
    case 6:
      return wrapFrame(6, offsetAdHocCall(payload.value, offsets));
    case 7:
      return wrapFrame(7, offsetNotificationProfile(payload.value, offsets));
    case 8:
      return wrapFrame(8, offsetChatFolder(payload.value, offsets));
    default:
      return frameRecord;
  }
}

function maxIds(frameRecords) {
  const max = { recipient: 0n, chat: 0n, call: 0n };
  for (const record of frameRecords) {
    const payload = framePayload(record);
    if (!payload) continue;
    const fields = parseMessage(payload.value);
    if (payload.field === 2) {
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id && id > max.recipient) max.recipient = id;
    } else if (payload.field === 3) {
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id && id > max.chat) max.chat = id;
    } else if (payload.field === 6) {
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id && id > max.call) max.call = id;
    }
  }
  return max;
}

function firstField(fields, fieldNo, wire) {
  return fields.find(field => field.field === fieldNo && (wire == null || field.wire === wire));
}

function bytesKey(prefix, bytes) {
  return `${prefix}:${Buffer.from(bytes).toString('hex')}`;
}

function recipientIdFromRecord(record) {
  const payload = framePayload(record);
  if (payload?.field !== 2) return undefined;
  return firstField(parseMessage(payload.value), 1, 0)?.value;
}

function chatIdFromRecord(record) {
  const payload = framePayload(record);
  if (payload?.field !== 3) return undefined;
  return firstField(parseMessage(payload.value), 1, 0)?.value;
}

function chatRecipientIdFromRecord(record) {
  const payload = framePayload(record);
  if (payload?.field !== 3) return undefined;
  return firstField(parseMessage(payload.value), 2, 0)?.value;
}

function recipientKeyFromPayload(payload) {
  const fields = parseMessage(payload);
  const contact = firstField(fields, 2, 2)?.value;
  if (contact) {
    const contactFields = parseMessage(contact);
    const aci = firstField(contactFields, 1, 2)?.value;
    if (aci?.length) return bytesKey('contact-aci', aci);
    const pni = firstField(contactFields, 2, 2)?.value;
    if (pni?.length) return bytesKey('contact-pni', pni);
    const e164 = firstField(contactFields, 4, 0)?.value;
    if (e164 != null) return `contact-e164:${e164.toString()}`;
    const username = firstField(contactFields, 3, 2)?.value;
    if (username?.length) return `contact-username:${username.toString('utf8')}`;
  }

  const group = firstField(fields, 3, 2)?.value;
  if (group) {
    const masterKey = firstField(parseMessage(group), 1, 2)?.value;
    if (masterKey?.length) return bytesKey('group-master', masterKey);
  }

  const distribution = firstField(fields, 4, 2)?.value;
  if (distribution) {
    const distributionId = firstField(parseMessage(distribution), 1, 2)?.value;
    if (distributionId?.length) return bytesKey('distribution', distributionId);
  }

  if (firstField(fields, 5, 2)) return 'self';
  if (firstField(fields, 6, 2)) return 'release-notes';

  const callLink = firstField(fields, 7, 2)?.value;
  if (callLink) {
    const rootKey = firstField(parseMessage(callLink), 1, 2)?.value;
    if (rootKey?.length) return bytesKey('call-link-root', rootKey);
  }

  return undefined;
}

function recipientKeyFromRecord(record) {
  const payload = framePayload(record);
  if (payload?.field !== 2) return undefined;
  return recipientKeyFromPayload(payload.value);
}

function buildSemanticMaps(oldFrames, newFrames) {
  const ids = maxIds(newFrames);
  const recipientOffset = ids.recipient + 1000000n;
  const chatOffset = ids.chat + 1000000n;

  const newRecipientByKey = new Map();
  for (const record of newFrames.filter(item => frameKind(item) === 'recipient')) {
    const id = recipientIdFromRecord(record);
    const key = recipientKeyFromRecord(record);
    if (id != null && key) {
      newRecipientByKey.set(key, id);
    }
  }

  const recipientMap = new Map();
  const oldDuplicateRecipientIds = new Set();
  for (const record of oldFrames.filter(item => frameKind(item) === 'recipient')) {
    const id = recipientIdFromRecord(record);
    if (id == null) continue;
    const key = recipientKeyFromRecord(record);
    const existing = key ? newRecipientByKey.get(key) : undefined;
    if (existing != null) {
      recipientMap.set(id.toString(), existing);
      oldDuplicateRecipientIds.add(id.toString());
    } else {
      recipientMap.set(id.toString(), id + recipientOffset);
    }
  }

  const newChatByRecipient = new Map();
  for (const record of newFrames.filter(item => frameKind(item) === 'chat')) {
    const id = chatIdFromRecord(record);
    const recipientId = chatRecipientIdFromRecord(record);
    if (id != null && recipientId != null) {
      newChatByRecipient.set(recipientId.toString(), id);
    }
  }

  const chatMap = new Map();
  const oldDuplicateChatIds = new Set();
  for (const record of oldFrames.filter(item => frameKind(item) === 'chat')) {
    const id = chatIdFromRecord(record);
    const recipientId = chatRecipientIdFromRecord(record);
    if (id == null || recipientId == null) continue;
    const mappedRecipientId = recipientMap.get(recipientId.toString()) ?? (recipientId + recipientOffset);
    const existingChatId = newChatByRecipient.get(mappedRecipientId.toString());
    if (existingChatId != null) {
      chatMap.set(id.toString(), existingChatId);
      oldDuplicateChatIds.add(id.toString());
    } else {
      chatMap.set(id.toString(), id + chatOffset);
    }
  }

  return {
    offsets: {
      recipient: { offset: recipientOffset, map: recipientMap },
      chat: { offset: chatOffset, map: chatMap },
      call: 0n,
    },
    oldDuplicateRecipientIds,
    oldDuplicateChatIds,
  };
}

function chatItemTimestamp(record) {
  const payload = framePayload(record);
  if (!payload || payload.field !== 4) return 0n;
  const fields = parseMessage(payload.value);
  return fields.find(field => field.field === 3 && field.wire === 0)?.value || 0n;
}

function stickerPackKey(record) {
  const payload = framePayload(record);
  if (payload?.field !== 5) return undefined;
  const packId = firstField(parseMessage(payload.value), 1, 2)?.value;
  return packId?.length ? Buffer.from(packId).toString('hex') : undefined;
}

function dedupeRecords(records) {
  const seenChatItems = new Set();
  const seenStickerPacks = new Set();
  const result = [];
  let droppedChatItems = 0;
  for (const record of records) {
    if (frameKind(record) === 'stickerPack') {
      const key = stickerPackKey(record);
      if (key && seenStickerPacks.has(key)) {
        continue;
      }
      if (key) seenStickerPacks.add(key);
      result.push(record);
      continue;
    }
    if (frameKind(record) !== 'chatItem') {
      result.push(record);
      continue;
    }
    const key = Buffer.from(record).toString('base64');
    if (seenChatItems.has(key)) {
      droppedChatItems += 1;
      continue;
    }
    seenChatItems.add(key);
    result.push(record);
  }
  return { records: result, droppedChatItems };
}

function summarize(records, files) {
  const counts = {};
  for (let i = 1; i < records.length; i += 1) {
    const kind = frameKind(records[i]);
    counts[kind] = (counts[kind] || 0) + 1;
  }
  return { records: records.length, backupInfoRecords: 1, frames: records.length - 1, counts, files: files.length };
}

function validateReference(id, known, errors, label, frameIndex) {
  if (id == null || id === 0n) return;
  if (!known.has(id.toString())) {
    errors.push(`frame ${frameIndex}: missing ${label} ${id.toString()}`);
  }
}

function validateRepeatedReferences(fields, fieldNos, known, errors, label, frameIndex) {
  for (const field of fields) {
    if (field.wire === 0 && fieldNos.includes(field.field)) {
      validateReference(field.value, known, errors, label, frameIndex);
    }
  }
}

function validateSendStatus(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  validateRepeatedReferences(fields, [1], known.recipients, errors, 'send status recipient', frameIndex);
}

function validateReaction(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  validateRepeatedReferences(fields, [2], known.recipients, errors, 'reaction author', frameIndex);
}

function validateQuote(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  validateRepeatedReferences(fields, [2], known.recipients, errors, 'quote author', frameIndex);
}

function validatePoll(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  for (const option of fields.filter(field => field.field === 3 && field.wire === 2)) {
    for (const vote of parseMessage(option.value).filter(field => field.field === 2 && field.wire === 2)) {
      const voteFields = parseMessage(vote.value);
      validateRepeatedReferences(voteFields, [1], known.recipients, errors, 'poll voter', frameIndex);
    }
  }
  for (const reaction of fields.filter(field => field.field === 5 && field.wire === 2)) {
    validateReaction(reaction.value, known, errors, frameIndex);
  }
}

function validateChatUpdate(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  for (const groupCall of fields.filter(field => field.field === 8 && field.wire === 2)) {
    const callFields = parseMessage(groupCall.value);
    validateRepeatedReferences(callFields, [3, 4], known.recipients, errors, 'group call recipient', frameIndex);
  }
  for (const pinMessage of fields.filter(field => field.field === 11 && field.wire === 2)) {
    const pinFields = parseMessage(pinMessage.value);
    validateRepeatedReferences(pinFields, [2], known.recipients, errors, 'pin author', frameIndex);
  }
}

function validateChatItem(payload, known, errors, frameIndex) {
  const fields = parseMessage(payload);
  validateRepeatedReferences(fields, [1], known.chats, errors, 'chat', frameIndex);
  validateRepeatedReferences(fields, [2], known.recipients, errors, 'author', frameIndex);
  for (const revision of fields.filter(field => field.field === 6 && field.wire === 2)) {
    validateChatItem(revision.value, known, errors, frameIndex);
  }
  for (const outgoing of fields.filter(field => field.field === 9 && field.wire === 2)) {
    for (const status of parseMessage(outgoing.value).filter(field => field.field === 1 && field.wire === 2)) {
      validateSendStatus(status.value, known, errors, frameIndex);
    }
  }
  for (const standard of fields.filter(field => field.field === 11 && field.wire === 2)) {
    const standardFields = parseMessage(standard.value);
    for (const quote of standardFields.filter(field => field.field === 1 && field.wire === 2)) {
      validateQuote(quote.value, known, errors, frameIndex);
    }
    for (const reaction of standardFields.filter(field => field.field === 6 && field.wire === 2)) {
      validateReaction(reaction.value, known, errors, frameIndex);
    }
  }
  for (const contact of fields.filter(field => field.field === 12 && field.wire === 2)) {
    for (const reaction of parseMessage(contact.value).filter(field => field.field === 2 && field.wire === 2)) {
      validateReaction(reaction.value, known, errors, frameIndex);
    }
  }
  for (const sticker of fields.filter(field => field.field === 13 && field.wire === 2)) {
    for (const reaction of parseMessage(sticker.value).filter(field => field.field === 2 && field.wire === 2)) {
      validateReaction(reaction.value, known, errors, frameIndex);
    }
  }
  for (const update of fields.filter(field => field.field === 15 && field.wire === 2)) {
    validateChatUpdate(update.value, known, errors, frameIndex);
  }
  for (const viewOnce of fields.filter(field => field.field === 18 && field.wire === 2)) {
    for (const reaction of parseMessage(viewOnce.value).filter(field => field.field === 2 && field.wire === 2)) {
      validateReaction(reaction.value, known, errors, frameIndex);
    }
  }
  for (const storyReply of fields.filter(field => field.field === 19 && field.wire === 2)) {
    for (const reaction of parseMessage(storyReply.value).filter(field => field.field === 3 && field.wire === 2)) {
      validateReaction(reaction.value, known, errors, frameIndex);
    }
  }
  for (const poll of fields.filter(field => field.field === 20 && field.wire === 2)) {
    validatePoll(poll.value, known, errors, frameIndex);
  }
  for (const adminDeleted of fields.filter(field => field.field === 22 && field.wire === 2)) {
    const adminFields = parseMessage(adminDeleted.value);
    validateRepeatedReferences(adminFields, [1], known.recipients, errors, 'admin deleted admin', frameIndex);
  }
}

function checkReferences(records) {
  const known = {
    recipients: new Set(),
    chats: new Set(),
    calls: new Set(),
  };
  const errors = [];
  for (let i = 1; i < records.length; i += 1) {
    const payload = framePayload(records[i]);
    if (!payload) continue;
    const fields = parseMessage(payload.value);
    if (payload.field === 2) {
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id != null) known.recipients.add(id.toString());
      for (const distributionItem of fields.filter(field => field.field === 4 && field.wire === 2)) {
        for (const list of parseMessage(distributionItem.value).filter(field => field.field === 3 && field.wire === 2)) {
          validateRepeatedReferences(parseMessage(list.value), [4], known.recipients, errors, 'distribution list member', i);
        }
      }
    } else if (payload.field === 3) {
      validateRepeatedReferences(fields, [2], known.recipients, errors, 'chat recipient', i);
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id != null) known.chats.add(id.toString());
    } else if (payload.field === 4) {
      validateChatItem(payload.value, known, errors, i);
    } else if (payload.field === 6) {
      validateRepeatedReferences(fields, [2], known.recipients, errors, 'ad hoc call recipient', i);
      const id = fields.find(field => field.field === 1 && field.wire === 0)?.value;
      if (id != null) known.calls.add(id.toString());
    } else if (payload.field === 7) {
      validateRepeatedReferences(fields, [7], known.recipients, errors, 'notification profile allowed member', i);
    } else if (payload.field === 8) {
      validateRepeatedReferences(fields, [7, 8], known.recipients, errors, 'chat folder recipient', i);
    }
  }
  return {
    recipients: known.recipients.size,
    chats: known.chats.size,
    calls: known.calls.size,
    errors,
  };
}

function decodeFilesList(buffer) {
  return decodeDelimited(buffer).flatMap(record => {
    const mediaName = parseMessage(record).find(field => field.field === 1 && field.wire === 2)?.value;
    return mediaName ? [mediaName.toString('utf8')] : [];
  });
}

function encodeFilesList(files) {
  return encodeDelimited(files.map(mediaName => encodeMessage([
    { field: 1, wire: 2, value: Buffer.from(mediaName, 'utf8') },
  ])));
}

function localMediaName(plaintextHash, localKey) {
  return createHash('sha256').update(Buffer.concat([plaintextHash, localKey])).digest('hex');
}

function scrubMissingLocalKeysInFrame(frameRecord, missingMediaNames) {
  if (!missingMediaNames.size) return frameRecord;
  const payload = framePayload(frameRecord);
  if (!payload) return frameRecord;
  if (payload.field !== 4) return frameRecord;
  return wrapFrame(payload.field, scrubChatItem(payload.value, missingMediaNames));
}

function scrubFilePointer(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    const locatorInfo = fields.find(field => field.field === 13 && field.wire === 2);
    if (!locatorInfo) return fields;
    const locatorFields = parseMessage(locatorInfo.value);
    const localKey = locatorFields.find(field => field.field === 9 && field.wire === 2)?.value;
    const plaintextHash = locatorFields.find(field => field.field === 10 && field.wire === 2)?.value;
    if (
      localKey &&
      plaintextHash &&
      localKey.length > 0 &&
      plaintextHash.length > 0 &&
      missingMediaNames.has(localMediaName(plaintextHash, localKey))
    ) {
      locatorInfo.value = encodeMessage(locatorFields.filter(field => field.field !== 9));
    }
    return fields;
  });
}

function scrubMessageAttachment(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], 0n, pointer => parseMessage(scrubFilePointer(encodeMessage(pointer), missingMediaNames)));
    return fields;
  });
}

function scrubQuote(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [4], 0n, quotedAttachment => {
      offsetNestedFields(quotedAttachment, [3], 0n, thumbnail => parseMessage(scrubMessageAttachment(encodeMessage(thumbnail), missingMediaNames)));
      return quotedAttachment;
    });
    return fields;
  });
}

function scrubStandardMessage(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], 0n, quote => parseMessage(scrubQuote(encodeMessage(quote), missingMediaNames)));
    offsetNestedFields(fields, [3], 0n, attachment => parseMessage(scrubMessageAttachment(encodeMessage(attachment), missingMediaNames)));
    offsetNestedFields(fields, [4], 0n, linkPreview => {
      offsetNestedFields(linkPreview, [3], 0n, image => parseMessage(scrubFilePointer(encodeMessage(image), missingMediaNames)));
      return linkPreview;
    });
    offsetNestedFields(fields, [5], 0n, longText => parseMessage(scrubFilePointer(encodeMessage(longText), missingMediaNames)));
    return fields;
  });
}

function scrubContactMessage(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], 0n, contact => {
      offsetNestedFields(contact, [6], 0n, avatar => parseMessage(scrubFilePointer(encodeMessage(avatar), missingMediaNames)));
      return contact;
    });
    return fields;
  });
}

function scrubStickerMessage(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], 0n, sticker => {
      offsetNestedFields(sticker, [5], 0n, data => parseMessage(scrubFilePointer(encodeMessage(data), missingMediaNames)));
      return sticker;
    });
    return fields;
  });
}

function scrubDirectStoryReply(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [1], 0n, textReply => {
      offsetNestedFields(textReply, [2], 0n, longText => parseMessage(scrubFilePointer(encodeMessage(longText), missingMediaNames)));
      return textReply;
    });
    return fields;
  });
}

function scrubChatItem(payload, missingMediaNames) {
  return rewriteNested(payload, fields => {
    offsetNestedFields(fields, [6], 0n, revision => parseMessage(scrubChatItem(encodeMessage(revision), missingMediaNames)));
    offsetNestedFields(fields, [11], 0n, standard => parseMessage(scrubStandardMessage(encodeMessage(standard), missingMediaNames)));
    offsetNestedFields(fields, [12], 0n, contact => parseMessage(scrubContactMessage(encodeMessage(contact), missingMediaNames)));
    offsetNestedFields(fields, [13], 0n, sticker => parseMessage(scrubStickerMessage(encodeMessage(sticker), missingMediaNames)));
    offsetNestedFields(fields, [18], 0n, viewOnce => {
      offsetNestedFields(viewOnce, [1], 0n, attachment => parseMessage(scrubMessageAttachment(encodeMessage(attachment), missingMediaNames)));
      return viewOnce;
    });
    offsetNestedFields(fields, [19], 0n, storyReply => parseMessage(scrubDirectStoryReply(encodeMessage(storyReply), missingMediaNames)));
    return fields;
  });
}

function collectFilePointerMediaName(payload, refs) {
  const fields = parseMessage(payload);
  const locatorInfo = fields.find(field => field.field === 13 && field.wire === 2);
  if (!locatorInfo) return;
  const locatorFields = parseMessage(locatorInfo.value);
  const localKey = locatorFields.find(field => field.field === 9 && field.wire === 2)?.value;
  const plaintextHash = locatorFields.find(field => field.field === 10 && field.wire === 2)?.value;
  if (localKey?.length && plaintextHash?.length) {
    refs.add(localMediaName(plaintextHash, localKey));
  }
}

function collectMessageAttachmentMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.field === 1 && field.wire === 2) {
      collectFilePointerMediaName(field.value, refs);
    }
  }
}

function collectQuoteMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.field !== 4 || field.wire !== 2) continue;
    for (const nested of parseMessage(field.value)) {
      if (nested.field === 3 && nested.wire === 2) {
        collectMessageAttachmentMediaRefs(nested.value, refs);
      }
    }
  }
}

function collectStandardMessageMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.wire !== 2) continue;
    if (field.field === 1) {
      collectQuoteMediaRefs(field.value, refs);
    } else if (field.field === 3) {
      collectMessageAttachmentMediaRefs(field.value, refs);
    } else if (field.field === 4) {
      for (const nested of parseMessage(field.value)) {
        if (nested.field === 3 && nested.wire === 2) {
          collectFilePointerMediaName(nested.value, refs);
        }
      }
    } else if (field.field === 5) {
      collectFilePointerMediaName(field.value, refs);
    }
  }
}

function collectContactMessageMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.field !== 1 || field.wire !== 2) continue;
    for (const nested of parseMessage(field.value)) {
      if (nested.field === 6 && nested.wire === 2) {
        collectFilePointerMediaName(nested.value, refs);
      }
    }
  }
}

function collectStickerMessageMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.field !== 1 || field.wire !== 2) continue;
    for (const nested of parseMessage(field.value)) {
      if (nested.field === 5 && nested.wire === 2) {
        collectFilePointerMediaName(nested.value, refs);
      }
    }
  }
}

function collectDirectStoryReplyMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.field !== 1 || field.wire !== 2) continue;
    for (const nested of parseMessage(field.value)) {
      if (nested.field === 2 && nested.wire === 2) {
        collectFilePointerMediaName(nested.value, refs);
      }
    }
  }
}

function collectChatItemMediaRefs(payload, refs) {
  for (const field of parseMessage(payload)) {
    if (field.wire !== 2) continue;
    if (field.field === 6) {
      collectChatItemMediaRefs(field.value, refs);
    } else if (field.field === 11) {
      collectStandardMessageMediaRefs(field.value, refs);
    } else if (field.field === 12) {
      collectContactMessageMediaRefs(field.value, refs);
    } else if (field.field === 13) {
      collectStickerMessageMediaRefs(field.value, refs);
    } else if (field.field === 18) {
      for (const nested of parseMessage(field.value)) {
        if (nested.field === 1 && nested.wire === 2) {
          collectMessageAttachmentMediaRefs(nested.value, refs);
        }
      }
    } else if (field.field === 19) {
      collectDirectStoryReplyMediaRefs(field.value, refs);
    }
  }
}

function collectMediaRefs(records) {
  const refs = new Set();
  for (let i = 1; i < records.length; i += 1) {
    const payload = framePayload(records[i]);
    if (payload?.field === 4) {
      collectChatItemMediaRefs(payload.value, refs);
    }
  }
  return refs;
}

function mergeRecords(oldRecords, newRecords, missingMediaNames) {
  const oldSourceFrames = oldRecords.slice(1).filter(record => frameKind(record) !== 'account');
  const newSourceFrames = newRecords.slice(1);
  const { offsets, oldDuplicateRecipientIds, oldDuplicateChatIds } =
    buildSemanticMaps(oldSourceFrames, newSourceFrames);
  const oldFrames = oldRecords
    .slice(1)
    .filter(record => frameKind(record) !== 'account')
    .filter(record => {
      if (frameKind(record) === 'recipient') {
        const id = recipientIdFromRecord(record);
        return id == null || !oldDuplicateRecipientIds.has(id.toString());
      }
      if (frameKind(record) === 'chat') {
        const id = chatIdFromRecord(record);
        return id == null || !oldDuplicateChatIds.has(id.toString());
      }
      return true;
    })
    .map(record => scrubMissingLocalKeysInFrame(record, missingMediaNames))
    .map(record => offsetFrame(record, offsets));
  const newFrames = newRecords
    .slice(1)
    .map(record => scrubMissingLocalKeysInFrame(record, missingMediaNames));
  const newNonChat = newFrames.filter(record => frameKind(record) !== 'chatItem');
  const oldNonChat = oldFrames.filter(record => frameKind(record) !== 'chatItem');
  const chatItems = [
    ...newFrames.filter(record => frameKind(record) === 'chatItem'),
    ...oldFrames.filter(record => frameKind(record) === 'chatItem'),
  ].sort((a, b) => (chatItemTimestamp(a) < chatItemTimestamp(b) ? -1 : chatItemTimestamp(a) > chatItemTimestamp(b) ? 1 : 0));
  return dedupeRecords([newRecords[0], ...newNonChat, ...oldNonChat, ...chatItems]).records;
}

async function writeEncryptedMain(records, outPath, newPassphraseFile, backupId) {
  const passphrase = await readPassphrase(newPassphraseFile);
  const { hmacKey, aesKey } = deriveMessageKeys(deriveBackupKey(passphrase), backupId);
  const compressed = gzipSync(encodeDelimited(records));
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-cbc', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const body = Buffer.concat([iv, encrypted]);
  const mac = createHmac('sha256', hmacKey).update(body).digest();
  await writeFile(outPath, Buffer.concat([body, mac]));
}

async function copyFiles(sourceSnapshot, outBaseDir, files) {
  const sourceBase = dirname(sourceSnapshot);
  for (const mediaName of files) {
    const src = join(sourceBase, 'files', mediaName.slice(0, 2), mediaName);
    const dst = join(outBaseDir, 'files', mediaName.slice(0, 2), mediaName);
    await mkdir(dirname(dst), { recursive: true });
    await copyFile(src, dst).catch(error => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
}

async function existingFiles(sourceSnapshot, files) {
  const sourceBase = dirname(sourceSnapshot);
  const existing = [];
  const missing = [];
  for (const mediaName of files) {
    const path = join(sourceBase, 'files', mediaName.slice(0, 2), mediaName);
    try {
      await readFile(path);
      existing.push(mediaName);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        missing.push(mediaName);
      } else {
        throw error;
      }
    }
  }
  return { existing, missing };
}

async function commandSummary(snapshotDir, passphraseFile) {
  const snapshot = await readSnapshot(snapshotDir, passphraseFile);
  console.log(JSON.stringify(summarize(snapshot.records, snapshot.files), null, 2));
}

async function commandCheckRefs(snapshotDir, passphraseFile) {
  const snapshot = await readSnapshot(snapshotDir, passphraseFile);
  const result = checkReferences(snapshot.records);
  console.log(JSON.stringify({
    recipients: result.recipients,
    chats: result.chats,
    calls: result.calls,
    errors: result.errors.length,
    firstErrors: result.errors.slice(0, 20),
  }, null, 2));
  if (result.errors.length) process.exitCode = 1;
}

async function commandCheckMediaRefs(snapshotDir, passphraseFile) {
  const snapshot = await readSnapshot(snapshotDir, passphraseFile);
  const refs = collectMediaRefs(snapshot.records);
  const listed = new Set(snapshot.files);
  const unlisted = [...refs].filter(mediaName => !listed.has(mediaName));
  const missing = [];
  const baseDir = dirname(snapshotDir);
  for (const mediaName of refs) {
    try {
      await readFile(join(baseDir, 'files', mediaName.slice(0, 2), mediaName));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        missing.push(mediaName);
      } else {
        throw error;
      }
    }
  }
  console.log(JSON.stringify({
    localPointerRefs: refs.size,
    listedFiles: listed.size,
    unlistedRefs: unlisted.length,
    missingRefFiles: missing.length,
  }, null, 2));
  if (unlisted.length || missing.length) process.exitCode = 1;
}

async function commandOfficialValidate(snapshotDir, passphraseFile, nativePath) {
  const snapshot = await readSnapshot(snapshotDir, passphraseFile);
  const defaultNativePath = process.env.LOCALAPPDATA
    ? join(
        process.env.LOCALAPPDATA,
        'Programs',
        'signal-desktop',
        'resources',
        'app.asar.unpacked',
        'node_modules',
        '@signalapp',
        'libsignal-client',
        'prebuilds',
        'win32-x64',
        '@signalapp+libsignal-client.node'
      )
    : undefined;
  const modulePath = nativePath || defaultNativePath;
  if (!modulePath) {
    throw new Error('Native libsignal path was not provided and LOCALAPPDATA is unset');
  }
  const require = createRequire(import.meta.url);
  const api = require(modulePath);
  const validator = {
    _nativeHandle: api.OnlineBackupValidator_New(snapshot.records[0], 1),
  };
  const errors = [];
  for (let i = 1; i < snapshot.records.length; i += 1) {
    try {
      api.OnlineBackupValidator_AddFrame(validator, snapshot.records[i]);
    } catch (error) {
      errors.push(`frame ${i}: ${error?.message || error}`);
    }
  }
  try {
    api.OnlineBackupValidator_Finalize(validator);
  } catch (error) {
    errors.push(`finalize: ${error?.message || error}`);
  }
  console.log(JSON.stringify({
    records: snapshot.records.length,
    frames: snapshot.records.length - 1,
    errors: errors.length,
    firstErrors: errors.slice(0, 20),
    nativePath: modulePath,
  }, null, 2));
  if (errors.length) process.exitCode = 1;
}

async function commandMerge(oldSnapshotDir, oldPass, newSnapshotDir, newPass, outBaseDir) {
  const oldSnapshot = await readSnapshot(oldSnapshotDir, oldPass);
  const newSnapshot = await readSnapshot(newSnapshotDir, newPass);
  const oldFiles = await existingFiles(oldSnapshotDir, oldSnapshot.files);
  const newFiles = await existingFiles(newSnapshotDir, newSnapshot.files);
  const missingMediaNames = new Set([...oldFiles.missing, ...newFiles.missing]);
  const mergedRecords = mergeRecords(oldSnapshot.records, newSnapshot.records, missingMediaNames);
  const mergedFiles = [...new Set([...newFiles.existing, ...oldFiles.existing])];
  const stamp = new Date().toISOString().replace(/\..+/, '').replace('T', '-').replace(/:/g, '-');
  const outSnapshot = join(outBaseDir, `signal-backup-${stamp}`);
  await mkdir(outSnapshot, { recursive: true });
  await mkdir(join(outBaseDir, 'files'), { recursive: true });
  await writeEncryptedMain(mergedRecords, join(outSnapshot, 'main'), newPass, newSnapshot.backupId);
  await writeFile(join(outSnapshot, 'metadata'), newSnapshot.metadata);
  await writeFile(join(outSnapshot, 'files'), encodeFilesList(mergedFiles));
  await copyFiles(newSnapshotDir, outBaseDir, newFiles.existing);
  await copyFiles(oldSnapshotDir, outBaseDir, oldFiles.existing);

  const verification = await readSnapshot(outSnapshot, newPass);
  console.log(JSON.stringify({
    outSnapshot,
    old: summarize(oldSnapshot.records, oldSnapshot.files),
    new: summarize(newSnapshot.records, newSnapshot.files),
    merged: summarize(verification.records, verification.files),
    skippedMissingMedia: missingMediaNames.size,
  }, null, 2));
}

async function commandCheckFiles(snapshotDir) {
  const files = decodeFilesList(await readFile(join(snapshotDir, 'files')));
  const baseDir = dirname(snapshotDir);
  const missing = [];
  for (const mediaName of files) {
    const path = join(baseDir, 'files', mediaName.slice(0, 2), mediaName);
    try {
      await readFile(path);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        missing.push(mediaName);
      } else {
        throw error;
      }
    }
  }
  console.log(JSON.stringify({ listed: files.length, uniqueListed: new Set(files).size, missing: missing.length }, null, 2));
  if (missing.length) process.exitCode = 1;
}

const [command, ...args] = process.argv.slice(2);
if (command === 'summary' && args.length === 2) {
  await commandSummary(...args);
} else if (command === 'check-files' && args.length === 1) {
  await commandCheckFiles(...args);
} else if (command === 'check-refs' && args.length === 2) {
  await commandCheckRefs(...args);
} else if (command === 'check-media-refs' && args.length === 2) {
  await commandCheckMediaRefs(...args);
} else if (command === 'official-validate' && (args.length === 2 || args.length === 3)) {
  await commandOfficialValidate(...args);
} else if (command === 'merge' && args.length === 5) {
  await commandMerge(...args);
} else {
  usage();
}
