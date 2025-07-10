import unorm from "unorm";
import crypto from "react-native-quick-crypto";
import { Buffer } from "@craftzdog/react-native-buffer";

const { pbkdf2Sync, createHash, randomBytes } = crypto;

export function mnemonicToSeed(
  mnemonic: string,
  password: string = ""
): Buffer {
  const mnemonicBuffer = new Buffer(mnemonic, "utf8");
  const saltBuffer = new Buffer(salt(password), "utf8");
  return pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
}

export function mnemonicToSeedHex(
  mnemonic: string,
  password: string = ""
): string {
  return mnemonicToSeed(mnemonic, password).toString("hex");
}

export function mnemonicToEntropy(
  mnemonic: string,
  wordslist: string[]
): string {
  const wordlist = wordslist;

  const words = mnemonic.split(" ");
  if (words.length % 3 !== 0) throw "Invalid mnemonic";

  // convert word indices to 11 bit binary strings
  const bits = words
    .map(function (word) {
      const index = wordlist.indexOf(word);
      return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropy = bits.slice(0, dividerIndex);
  const checksum = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropy.match(/(.{1,8})/g)?.map(function (bin) {
    return parseInt(bin, 2);
  });

  if (!entropyBytes) throw "no entropyBytes";

  const entropyBuffer = new Buffer(entropyBytes);
  const newChecksum = checksumBits(entropyBuffer);

  if (newChecksum !== checksum) throw "Invalid mnemonic checksum";

  return entropyBuffer.toString("hex");
}

export function entropyToMnemonic(
  entropy: string,
  wordslist: string[]
): string {
  const wordlist = wordslist;

  const entropyBuffer = new Buffer(entropy, "hex");
  const entropyBits = bytesToBinary([].slice.call(entropyBuffer));
  const checksum = checksumBits(entropyBuffer);

  const bits = entropyBits + checksum;
  const chunks = bits.match(/(.{1,11})/g);

  if (!chunks) throw "no chunks";

  const words = chunks.map((binary: any) => {
    const index = parseInt(binary, 2);
    return wordlist[index];
  });

  return words.join(" ");
}

export function generateMnemonic(
  strength: number = 128,
  wordlist: string[]
): string {
  const randomBytesBuffer = Buffer.from(randomBytes(strength / 8));
  return entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist);
}

export function validateMnemonic(mnemonic: string, wordlist: string[]) {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

function checksumBits(entropyBuffer: Buffer) {
  const hash = createHash("sha256").update(entropyBuffer).digest();

  // Calculated constants from BIP39
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;

  return bytesToBinary([].slice.call(hash)).slice(0, CS);
}

function salt(password: string) {
  //Using unorm to get proper unicode string, string.normalize might not work well for some verions of browser
  return "mnemonic" + (unorm.nfkd(password) || "");
}

//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes: number[]) {
  return bytes
    .map(function (x) {
      return lpad(x.toString(2), "0", 8);
    })
    .join("");
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) str = padString + str;
  return str;
}
