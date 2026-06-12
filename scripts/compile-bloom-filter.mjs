import fs from 'fs';
import path from 'path';

// Exact same Murmur3 hash implementation as the worker
function hashMurmur3(key, seed) {
  let remainder = key.length & 3;
  let bytes = key.length - remainder;
  let h1 = seed;
  let c1 = 0xcc9e2d51;
  let c2 = 0x1b873593;
  let i = 0;
  while (i < bytes) {
    let k1 =
      ((key.charCodeAt(i) & 0xff)) |
      ((key.charCodeAt(++i) & 0xff) << 8) |
      ((key.charCodeAt(++i) & 0xff) << 16) |
      ((key.charCodeAt(++i) & 0xff) << 24);
    ++i;
    k1 = ((((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16))) & 0xffffffff;
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = ((((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16))) & 0xffffffff;
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (((h1 * 5) + 0xe6546b64)) & 0xffffffff;
  }
  let k1 = 0;
  switch (remainder) {
    case 3:
      k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16;
    case 2:
      k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8;
    case 1:
      k1 ^= (key.charCodeAt(i) & 0xff);
      k1 = ((((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16))) & 0xffffffff;
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = ((((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16))) & 0xffffffff;
      h1 ^= k1;
  }
  h1 ^= key.length;
  h1 ^= h1 >>> 16;
  h1 = ((((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16))) & 0xffffffff;
  h1 ^= h1 >>> 13;
  h1 = ((((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16))) & 0xffffffff;
  h1 ^= h1 >>> 16;
  return h1 >>> 0;
}

class BloomFilter {
  constructor(sizeInBytes, numHashFunctions) {
    this.sizeInBytes = sizeInBytes;
    this.numHashFunctions = numHashFunctions;
    this.bitArray = new Uint8Array(sizeInBytes);
  }

  add(str) {
    const sizeInBits = this.sizeInBytes * 8;
    const h1 = hashMurmur3(str, 0);
    const h2 = hashMurmur3(str, 1);
    for (let i = 0; i < this.numHashFunctions; i++) {
      const bitPosition = Math.abs((h1 + i * h2) % sizeInBits);
      const byteIndex = Math.floor(bitPosition / 8);
      const bitIndex = bitPosition % 8;
      this.bitArray[byteIndex] |= (1 << bitIndex);
    }
  }
}

const BLOOM_FILTER_SIZE = 627661;
const BLOOM_FILTER_HASHES = 7;

async function compile() {
  const sourcePath = path.resolve('output/doh/doh_combined.txt');
  console.log(`Reading blocklist from ${sourcePath}...`);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Blocklist source file not found at ${sourcePath}`);
  }
  const text = fs.readFileSync(sourcePath, 'utf-8');
  const lines = text.split('\n');
  const domains = [];
  for (const line of lines) {
    const d = line.trim().toLowerCase();
    if (d && !d.startsWith('#')) {
      domains.push(d);
    }
  }

  console.log(`Loaded ${domains.length} domains. Building Bloom Filter...`);
  const filter = new BloomFilter(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES);
  for (const d of domains) {
    filter.add(d);
  }

  console.log('Writing bloomfilter.bin...');
  fs.writeFileSync('bloomfilter.bin', Buffer.from(filter.bitArray));

  // Write blocklist.txt metadata file
  // Format: lastSyncAt|totalDomains|shardCount|sourceBytes|sourceEtag
  const lastSyncAt = Date.now();
  const sourceBytes = Buffer.from(text).length;
  const crypto = await import('crypto');
  const hash = crypto.createHash('md5').update(text).digest('hex');
  const sourceEtag = `W/"${hash}"`;

  const metaContent = [
    lastSyncAt,
    domains.length,
    1, // shardCount = 1 (dummy)
    sourceBytes,
    sourceEtag
  ].join('|');

  console.log('Writing blocklist.txt metadata...');
  fs.writeFileSync('blocklist.txt', metaContent);
  console.log('Bloom Filter & Metadata successfully compiled!');
}

compile().catch(err => {
  console.error(err);
  process.exit(1);
});
