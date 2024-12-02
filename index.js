"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Wordlists = void 0;
exports.mnemonicToSeed = mnemonicToSeed;
exports.mnemonicToSeedHex = mnemonicToSeedHex;
exports.mnemonicToEntropy = mnemonicToEntropy;
exports.entropyToMnemonic = entropyToMnemonic;
exports.generateMnemonic = generateMnemonic;
exports.validateMnemonic = validateMnemonic;
var unorm_1 = require("unorm");
var react_native_quick_crypto_1 = require("react-native-quick-crypto");
var react_native_buffer_1 = require("@craftzdog/react-native-buffer");
var cs_json_1 = require("./wordlists/cs.json");
var en_json_1 = require("./wordlists/en.json");
var es_json_1 = require("./wordlists/es.json");
var fr_json_1 = require("./wordlists/fr.json");
var it_json_1 = require("./wordlists/it.json");
var ja_json_1 = require("./wordlists/ja.json");
var ko_json_1 = require("./wordlists/ko.json");
var pt_json_1 = require("./wordlists/pt.json");
var zh_json_1 = require("./wordlists/zh.json");
var pbkdf2Sync = react_native_quick_crypto_1.default.pbkdf2Sync,
  createHash = react_native_quick_crypto_1.default.createHash,
  randomBytes = react_native_quick_crypto_1.default.randomBytes;
exports.Wordlists = {
  cs: cs_json_1.default,
  en: en_json_1.default,
  es: es_json_1.default,
  fr: fr_json_1.default,
  ja: ja_json_1.default,
  it: it_json_1.default,
  ko: ko_json_1.default,
  pt: pt_json_1.default,
  zh: zh_json_1.default,
};
function mnemonicToSeed(mnemonic, password) {
  if (password === void 0) {
    password = "";
  }
  var mnemonicBuffer = new react_native_buffer_1.Buffer(mnemonic, "utf8");
  var saltBuffer = new react_native_buffer_1.Buffer(salt(password), "utf8");
  return pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
}
function mnemonicToSeedHex(mnemonic, password) {
  if (password === void 0) {
    password = "";
  }
  return mnemonicToSeed(mnemonic, password).toString("hex");
}
function mnemonicToEntropy(mnemonic, wordslist) {
  var _a;
  var wordlist = wordslist || en_json_1.default;
  var words = mnemonic.split(" ");
  if (words.length % 3 !== 0) throw "Invalid mnemonic";
  // convert word indices to 11 bit binary strings
  var bits = words
    .map(function (word) {
      var index = wordlist.indexOf(word);
      return lpad(index.toString(2), "0", 11);
    })
    .join("");
  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / 33) * 32;
  var entropy = bits.slice(0, dividerIndex);
  var checksum = bits.slice(dividerIndex);
  // calculate the checksum and compare
  var entropyBytes =
    (_a = entropy.match(/(.{1,8})/g)) === null || _a === void 0
      ? void 0
      : _a.map(function (bin) {
          return parseInt(bin, 2);
        });
  if (!entropyBytes) throw "no entropyBytes";
  var entropyBuffer = new react_native_buffer_1.Buffer(entropyBytes);
  var newChecksum = checksumBits(entropyBuffer);
  if (newChecksum !== checksum) throw "Invalid mnemonic checksum";
  return entropyBuffer.toString("hex");
}
function entropyToMnemonic(entropy, wordslist) {
  var wordlist = wordslist || en_json_1.default;
  var entropyBuffer = new react_native_buffer_1.Buffer(entropy, "hex");
  var entropyBits = bytesToBinary([].slice.call(entropyBuffer));
  var checksum = checksumBits(entropyBuffer);
  var bits = entropyBits + checksum;
  var chunks = bits.match(/(.{1,11})/g);
  if (!chunks) throw "no chunks";
  var words = chunks.map(function (binary) {
    var index = parseInt(binary, 2);
    return wordlist[index];
  });
  return words.join(" ");
}
function generateMnemonic(strength, wordlist) {
  if (strength === void 0) {
    strength = 128;
  }
  var randomBytesBuffer = react_native_buffer_1.Buffer.from(
    randomBytes(strength / 8)
  );
  return entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist);
}
function validateMnemonic(mnemonic, wordlist) {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}
function checksumBits(entropyBuffer) {
  var hash = createHash("sha256").update(entropyBuffer).digest();
  // Calculated constants from BIP39
  var ENT = entropyBuffer.length * 8;
  var CS = ENT / 32;
  return bytesToBinary([].slice.call(hash)).slice(0, CS);
}
function salt(password) {
  //Using unorm to get proper unicode string, string.normalize might not work well for some verions of browser
  return "mnemonic" + (unorm_1.default.nfkd(password) || "");
}
//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes) {
  return bytes
    .map(function (x) {
      return lpad(x.toString(2), "0", 8);
    })
    .join("");
}
function lpad(str, padString, length) {
  while (str.length < length) str = padString + str;
  return str;
}
