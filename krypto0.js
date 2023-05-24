// void chacha20_block(uint32_t state[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter);
// void chacha20_encrypt(uint8_t key[32], uint8_t nonce[12], uint32_t *counter, uint8_t *position, uint8_t *plaintext, size_t l);
// void poly1305_key_gen(uint8_t out[32], uint8_t key[32], uint8_t nonce[12]);
// void poly1305_mac(uint8_t out[16], uint8_t km[32], uint8_t *m, size_t l);
// void chacha20_aead_encrypt0(uint8_t *aad, size_t aad_len, uint8_t key[32], uint8_t nonce[12], uint8_t *plaintext, size_t plaintext_len, uint8_t tag[16]);
// void chacha20_aead_decrypt(uint8_t key[32], uint8_t *ciphertext, size_t ciphertext_len, uint8_t nonce[12], uint8_t *aad, size_t aad_len, uint8_t tag[16]);
// void *malloc_(size_t size);
// void free_(void *ptr);

function chacha20_block(key, nonce, counter) {
    let statePtr = Module._malloc_(16 * 4);
    let keyPtr = Module._malloc_(32);
    let noncePtr = Module._malloc_(12);

    let stateArr = new Uint32Array(Module.HEAPU8.buffer, statePtr, 16);
    let keyArr = new Uint8Array(Module.HEAPU8.buffer, keyPtr, 32);
    let nonceArr = new Uint8Array(Module.HEAPU8.buffer, noncePtr, 12);

    if (key !== undefined) {
        keyArr.set(key);
    } else {
        keyArr.fill(0);
    }
    if (nonce !== undefined) {
        nonceArr.set(nonce);
    } else {
        nonceArr.fill(0);
    }
    if (counter === undefined) {
        counter = 0;
    }

    Module._chacha20_block(statePtr, keyPtr, noncePtr, counter);

    let state = new ArrayBuffer(16 * 4);
    new Uint32Array(state).set(stateArr);

    Module._free_(statePtr);
    Module._free_(keyPtr);
    Module._free_(noncePtr);

    return state;
}

function chacha20_encrypt(key, nonce, counter, position, plaintext) {
    const plaintext_len = plaintext === undefined ? 0 : plaintext.length;
    
    let keyPtr = Module._malloc_(32);
    let noncePtr = Module._malloc_(12);
    let counterPtr = Module._malloc_(4);
    let positionPtr = Module._malloc_(4);
    let plaintextPtr = Module._malloc_(plaintext_len);

    let keyArr = new Uint8Array(Module.HEAPU8.buffer, keyPtr, 32);
    let nonceArr = new Uint8Array(Module.HEAPU8.buffer, noncePtr, 12);
    let counterArr = new Uint32Array(Module.HEAPU8.buffer, counterPtr, 1);
    let positionArr = new Uint32Array(Module.HEAPU8.buffer, positionPtr, 1);
    let plaintextArr = new Uint8Array(Module.HEAPU8.buffer, plaintextPtr, plaintext_len);

    if (key !== undefined)
        keyArr.set(key);
    else
        keyArr.fill(0);
    if (nonce !== undefined)
        nonceArr.set(nonce);
    else
        nonceArr.fill(0);
    if (counter === undefined)
        counter = 0;
    if (position === undefined)
        position = 64;
    counterArr[0] = counter;
    positionArr[0] = position;
    plaintextArr.set(plaintext);

    Module._chacha20_encrypt(keyPtr, noncePtr, counterPtr, positionPtr, plaintextPtr, plaintext_len);

    let ciphertext = new Uint8Array(plaintext.length);
    ciphertext.set(plaintextArr);

    Module._free_(keyPtr);
    Module._free_(noncePtr);
    Module._free_(counterPtr);
    Module._free_(positionPtr);
    Module._free_(plaintextPtr);

    return ciphertext;
}

function poly1305_key_gen(key, nonce) {
    let keyPtr = Module._malloc_(32);
    let noncePtr = Module._malloc_(12);
    let outPtr = Module._malloc_(32);

    let keyArr = new Uint8Array(Module.HEAPU8.buffer, keyPtr, 32);
    let nonceArr = new Uint8Array(Module.HEAPU8.buffer, noncePtr, 12);
    let outArr = new Uint8Array(Module.HEAPU8.buffer, outPtr, 32);

    if (key !== undefined)
        keyArr.set(key);
    else
        keyArr.fill(0);
    if (nonce !== undefined)
        nonceArr.set(nonce);
    else
        nonceArr.fill(0);
    
    Module._poly1305_key_gen(outPtr, keyPtr, noncePtr);

    let out = new Uint8Array(32);
    out.set(outArr);

    Module._free_(keyPtr);
    Module._free_(noncePtr);
    Module._free_(outPtr);

    return out;
}

function poly1305_mac(km, m) {
    const m_len = m === undefined ? 0 : m.length;

    let kmPtr = Module._malloc_(32);
    let mPtr = Module._malloc_(m_len);
    let outPtr = Module._malloc_(16);

    let kmArr = new Uint8Array(Module.HEAPU8.buffer, kmPtr, 32);
    let mArr = new Uint8Array(Module.HEAPU8.buffer, mPtr, m_len);
    let outArr = new Uint8Array(Module.HEAPU8.buffer, outPtr, 16);

    if (km !== undefined)
        kmArr.set(km);
    else
        kmArr.fill(0);
    if (m !== undefined)
        mArr.set(m);
    else
        mArr.fill(0);
    
    Module._poly1305_mac(outPtr, kmPtr, mPtr, m_len);

    let out = new Uint8Array(16);
    out.set(outArr);

    Module._free_(kmPtr);
    Module._free_(mPtr);
    Module._free_(outPtr);

    return out;
}

function chacha20_aead_encrypt0(aad, key, nonce, plaintext) {
    const aad_len = aad === undefined ? 0 : aad.length;

    let aadPtr = Module._malloc_(aad_len);
    let keyPtr = Module._malloc_(32);
    let noncePtr = Module._malloc_(12);
    let plaintextPtr = Module._malloc_(plaintext.length);
    let tagPtr = Module._malloc_(16);

    let aadArr = new Uint8Array(Module.HEAPU8.buffer, aadPtr, aad_len);
    let keyArr = new Uint8Array(Module.HEAPU8.buffer, keyPtr, 32);
    let nonceArr = new Uint8Array(Module.HEAPU8.buffer, noncePtr, 12);
    let plaintextArr = new Uint8Array(Module.HEAPU8.buffer, plaintextPtr, plaintext.length);
    let tagArr = new Uint8Array(Module.HEAPU8.buffer, tagPtr, 16);

    if (aad !== undefined)
        aadArr.set(aad);
    else
        aadArr.fill(0);

    if (key !== undefined)
        keyArr.set(key);
    else
        keyArr.fill(0);
    
    if (nonce !== undefined)
        nonceArr.set(nonce);
    else
        nonceArr.fill(0);
    
    plaintextArr.set(plaintext);

    Module._chacha20_aead_encrypt0(aadPtr, aad_len, keyPtr, noncePtr, plaintextPtr, plaintext.length, tagPtr);
    
    let tag = new Uint8Array(16);
    tag.set(tagArr);

    let encryptedFile = new Uint8Array(plaintext.length);
    encryptedFile.set(plaintextArr);

    Module._free_(aadPtr);
    Module._free_(keyPtr);
    Module._free_(noncePtr);
    Module._free_(plaintextPtr);
    Module._free_(tagPtr);

    return [tag, encryptedFile];
}

function chacha20_aead_decrypt(aad, key, nonce, ciphertext) {
    const aad_len = aad === undefined ? 0 : aad.length;

    let aadPtr = Module._malloc_(aad_len);
    let keyPtr = Module._malloc_(32);
    let noncePtr = Module._malloc_(12);
    let ciphertextPtr = Module._malloc_(ciphertext.length);
    let tagPtr = Module._malloc_(16);

    let aadArr = new Uint8Array(Module.HEAPU8.buffer, aadPtr, aad_len);
    let keyArr = new Uint8Array(Module.HEAPU8.buffer, keyPtr, 32);
    let nonceArr = new Uint8Array(Module.HEAPU8.buffer, noncePtr, 12);
    let ciphertextArr = new Uint8Array(Module.HEAPU8.buffer, ciphertextPtr, ciphertext.length);
    let tagArr = new Uint8Array(Module.HEAPU8.buffer, tagPtr, 16);

    if (aad !== undefined)
        aadArr.set(aad);
    else
        aadArr.fill(0);

    if (key !== undefined)
        keyArr.set(key);
    else
        keyArr.fill(0);
    
    if (nonce !== undefined)
        nonceArr.set(nonce);
    else
        nonceArr.fill(0);
    
    ciphertextArr.set(ciphertext);

    Module._chacha20_aead_decrypt(keyPtr, ciphertextPtr, ciphertext.length, noncePtr, aadPtr, aad_len, tagPtr);
    
    let tag = new Uint8Array(16);
    tag.set(tagArr);

    let decryptedFile = new Uint8Array(ciphertext.length);
    decryptedFile.set(ciphertextArr);

    Module._free_(aadPtr);
    Module._free_(keyPtr);
    Module._free_(noncePtr);
    Module._free_(ciphertextPtr);
    Module._free_(tagPtr);

    return [tag, decryptedFile];
}

let allIntervals = [];


let fileInputE = new Uint8Array();
let fileNameE = "";
document.getElementById('filefe').addEventListener("change", function (e) {
    if (e.target.files.length == 0) return;
    const reader = new FileReader();
    const n = e.target.files[0].name;
    reader.onload = function () {
        fileInputE = new Uint8Array(reader.result);
        fileNameE = n;
        document.getElementById("filesizefe").value = fileInputE.length;
    }
    reader.readAsArrayBuffer(e.target.files[0]);
});

let fileInputD = new Uint8Array();
let fileNameD = "";
document.getElementById('filefd').addEventListener("change", function (e) {
    if (e.target.files.length == 0) return;
    const reader = new FileReader();
    const n = e.target.files[0].name;
    reader.onload = function () {
        fileInputD = new Uint8Array(reader.result);
        fileNameD = n;
        document.getElementById("filesizefd").value = fileInputD.length;
    }
    reader.readAsArrayBuffer(e.target.files[0]);
});


let globalValues = {};

/**
 * compare two binary arrays for equality
 * @param {(ArrayBuffer|ArrayBufferView)} a
 * @param {(ArrayBuffer|ArrayBufferView)} b 
 */
function equal(a, b) {
    if (a === b) {
        return true;
    }
    if (a instanceof ArrayBuffer) a = new Uint8Array(a, 0);
    if (b instanceof ArrayBuffer) b = new Uint8Array(b, 0);
    if (a.byteLength != b.byteLength) return false;
    if (aligned32(a) && aligned32(b))
      return equal32(a, b);
    if (aligned16(a) && aligned16(b))
      return equal16(a, b);
    return equal8(a, b);
  }
  
  function equal8(a, b) {
    const ua = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    const ub = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    return compare(ua, ub);
  }
  function equal16(a, b) {
    const ua = new Uint16Array(a.buffer, a.byteOffset, a.byteLength / 2);
    const ub = new Uint16Array(b.buffer, b.byteOffset, b.byteLength / 2);
    return compare(ua, ub);
  }
  function equal32(a, b) {
    const ua = new Uint32Array(a.buffer, a.byteOffset, a.byteLength / 4);
    const ub = new Uint32Array(b.buffer, b.byteOffset, b.byteLength / 4);
    return compare(ua, ub);
  }
  
  function compare(a, b) {
    for (let i = a.length; -1 < i; i -= 1) {
      if ((a[i] !== b[i])) return false;
    }
    return true;
  }
  
  function aligned16(a) {
    return (a.byteOffset % 2 === 0) && (a.byteLength % 2 === 0);
  }
  
  function aligned32(a) {
    return (a.byteOffset % 4 === 0) && (a.byteLength % 4 === 0);
  }
  

function filterVal(val) {
    let o = "";
    for (let i = 0; i < val.length; i++) {
        let c = val.charCodeAt(i);
        if (c >= 32 && c < 127) {
            o += val[i];
        } else {
            o += ".";
        }
    }
    return o;
}

function formatHex(val, len) {
    let formatted = val.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    let match = formatted.match(/..?/g);
    let v = match === null ? "" : match.join(" ");
    if (v.length < len * 3 - 1 && formatted.length % 2 === 0 && v.length > 0) {
        v += " ";
    }
    return v;
}

function setHexValue(id, hex) {
    hex = hex.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    let hexEl = document.getElementById(id + "hex");
    hexEl.value = hex;
}

function loadTestVectors() {
    document.getElementById("a11").addEventListener("click", () => {
        document.getElementById("keyhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("noncehex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("counter").value = "0";
    });
    document.getElementById("a12").addEventListener("click", () => {
        document.getElementById("keyhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("noncehex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("counter").value = "1";
    });
    document.getElementById("a13").addEventListener("click", () => {
        document.getElementById("keyhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
        document.getElementById("noncehex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("counter").value = "1";
    });
    document.getElementById("a14").addEventListener("click", () => {
        document.getElementById("keyhex").value = "00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("noncehex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("counter").value = "2";
    });
    document.getElementById("a15").addEventListener("click", () => {
        document.getElementById("keyhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("noncehex").value = "00 00 00 00 00 00 00 00 00 00 00 02";
        document.getElementById("counter").value = "0";
    });
    document.getElementById("a21").addEventListener("click", () => {
        document.getElementById("keyEhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("nonceEhex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("counterE").value = "0";
        document.getElementById("plaintexthex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a22").addEventListener("click", () => {
        document.getElementById("keyEhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
        document.getElementById("nonceEhex").value = "00 00 00 00 00 00 00 00 00 00 00 02";
        document.getElementById("counterE").value = "1";
        document.getElementById("plaintext").value = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    });
    document.getElementById("a23").addEventListener("click", () => {
        document.getElementById("keyEhex").value = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0";
        document.getElementById("nonceEhex").value = "00 00 00 00 00 00 00 00 00 00 00 02";
        document.getElementById("counterE").value = "42";
        document.getElementById("plaintextb64").value = btoa("'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.");
    });

    document.getElementById("a31").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a32").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e";
        document.getElementById("mac").value = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    });
    document.getElementById("a33").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("mac").value = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    });
    document.getElementById("a34").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0";
        document.getElementById("macb64").value = btoa("'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.");
    });
    document.getElementById("a35").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF";
    });
    document.getElementById("a36").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF";
        document.getElementById("machex").value = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a37").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a38").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01";
    });
    document.getElementById("a39").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF";
    });
    document.getElementById("a310").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00 33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a311").addEventListener("click", () => {
        document.getElementById("keyPhex").value = "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("machex").value = "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00 33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    });


    document.getElementById("a41").addEventListener("click", () => {
        document.getElementById("keyKhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        document.getElementById("nonceKhex").value = "00 00 00 00 00 00 00 00 00 00 00 00";
    });
    document.getElementById("a42").addEventListener("click", () => {
        document.getElementById("keyKhex").value = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01";
        document.getElementById("nonceKhex").value = "00 00 00 00 00 00 00 00 00 00 00 02";
    });
    document.getElementById("a43").addEventListener("click", () => {
        document.getElementById("keyKhex").value = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0";
        document.getElementById("nonceKhex").value = "00 00 00 00 00 00 00 00 00 00 00 02";
    });


}

loadTestVectors();

function loadValues(id, max) {
    let raw = document.getElementById(id);
    let b64 = document.getElementById(id + "b64");
    let hex = document.getElementById(id + "hex");

    raw.maxLength = max;
    hex.maxLength = max * 3 - 1;
    b64.maxLength = ((4 * max / 3) + 3) & ~3

    let values = ["", "", ""];

    hex.addEventListener("input", (e) => {
        const val = formatHex(hex.value, max);
        if (val !== hex.value) {
            let a = hex.selectionStart;
            hex.value = val;
            if ((a + 1) % 3 === 0) {
                a++;
            }
            hex.selectionStart = a;
            hex.selectionEnd = a;
        }
    });

    allIntervals.push(() => {
        if (values[0] !== raw.value) {
            globalValues[id] = Uint8Array.from(raw.value, c => c.charCodeAt(0));

            b64.value = btoa(raw.value);
            hex.value = formatHex([...globalValues[id]].map(c => c.toString(16).padStart(2, "0")).join(""), max);
        } else if (values[1] !== b64.value) {
            try {
                globalValues[id] = Uint8Array.from(atob(b64.value), c => c.charCodeAt(0));

                raw.value = filterVal(atob(b64.value));
                hex.value = formatHex([...globalValues[id]].map(c => c.toString(16).padStart(2, "0")).join(""), max);
            } catch (e) {
            }
        } else if (values[2] !== hex.value) {
            try {
                globalValues[id] = Uint8Array.from(hex.value.trim().split(" ").filter(n => n.trim() !== "").map(s => parseInt(s, 16)));

                raw.value = filterVal(String.fromCharCode(...globalValues[id]));
                b64.value = btoa(String.fromCharCode(...globalValues[id]));
            } catch (e) {
            }
        }
        values[0] = raw.value;
        values[1] = b64.value;
        values[2] = hex.value;
    });
}

function loadCounter(id) {
    let counter = document.getElementById(id);
    counter.addEventListener("input", (e) => {
        let val = counter.value.replace(/[^0-9]/g, "");
        if (val !== counter.value) {
            counter.value = val;
        }
    });
    let values = [""];
    allIntervals.push(() => {
        if (values[0] !== counter.value) {
            globalValues[id] = parseInt(counter.value.replace(/[^0-9]/g, ""));
        }
        values[0] = counter.value;
    });
}


// file encryption
loadValues("keyfe", 32);
loadValues("noncefe", 12);
loadValues("aadfe", 1024 * 1024);

// file decryption
loadValues("keyfd", 32);
loadValues("noncefd", 12);
loadValues("aadfd", 1024 * 1024);

// chacha20 block
loadValues("key", 32);
loadValues("nonce", 12);
loadCounter("counter");

// chacha20 enc
loadValues("keyE", 32);
loadValues("nonceE", 12);
loadCounter("counterE");
loadValues("plaintext", 1024 * 1024);

// Poly1305 Message Authentication Code
loadValues("keyP", 32);
loadValues("mac", 1024 * 1024);

// Poly1305 Key Generation Using ChaCha20
loadValues("keyK", 32);
loadValues("nonceK", 12);

function hexprint(id, out) {
    let div = document.getElementById(id);
    div.innerHTML = "";
    for (let i = 0; i < out.length; i += 16) {
        let row = document.createElement("div");
        {
            let label = document.createElement("span");
            label.innerText = "0x" + i.toString(16).padStart(4, "0") + ": ";
            label.style.userSelect = "none";
            row.appendChild(label);
        }
        {
            let value = document.createElement("span");
            value.innerText = [...out.subarray(i, i + 16)].map(v => v.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
            row.appendChild(value);
        }
        {
            let value = document.createElement("span");
            let str = String.fromCharCode(...out.subarray(i, i + 16));
            value.style.userSelect = "none";
            value.innerText = str.replace(/[\x00-\x1F\x7F-\xFF]/g, ".");
            row.appendChild(value);
        }
        div.appendChild(row);
    }
}

var downloadBlob, downloadURL;

downloadBlob = function (data, fileName, mimeType) {
    var blob, url;
    blob = new Blob([data], {
        type: mimeType
    });
    url = window.URL.createObjectURL(blob);
    downloadURL(url, fileName);
    setTimeout(function () {
        return window.URL.revokeObjectURL(url);
    }, 1000);
};

downloadURL = function (data, fileName) {
    var a;
    a = document.createElement('a');
    a.href = data;
    a.download = fileName;
    document.body.appendChild(a);
    a.style = 'display: none';
    a.click();
    a.remove();
};

let fileEncryptedCache = undefined;
let fileDecryptedCache = undefined;
document.getElementById("download1").addEventListener("click", () => {
    downloadBlob(fileEncryptedCache[1], fileNameE + ".encrypted", "application/octet-stream");
});
document.getElementById("download2").addEventListener("click", () => {
    const data = new Uint8Array(fileEncryptedCache[1].length + 16);
    data.set(fileEncryptedCache[0]);
    data.set(fileEncryptedCache[1], 16);
    downloadBlob(data, fileNameE + ".encrypted", "application/octet-stream");
});
document.getElementById("download3").addEventListener("click", () => {
    const data = new Uint8Array(fileEncryptedCache[1].length + 16);
    data.set(fileEncryptedCache[1]);
    data.set(fileEncryptedCache[0], fileEncryptedCache[1].length);
    downloadBlob(data, fileNameE + ".encrypted", "application/octet-stream");
});
document.getElementById("download4").addEventListener("click", () => {
    if (fileNameD.endsWith(".encrypted")) {
        downloadBlob(fileDecryptedCache, fileNameD.slice(0, -10), "application/octet-stream");
    } else {
        downloadBlob(fileDecryptedCache, fileNameD + ".decrypted", "application/octet-stream");
    }
});


Module["postRun"] = () => {

    let globalValuesCache = {};
    allIntervals.push(() => {
        let needUpdate = false;
        if (globalValues["key"] !== undefined && (globalValuesCache["key"] === undefined || !equal(globalValuesCache["key"], globalValues["key"]))) {
            globalValuesCache["key"] = globalValues["key"];
            needUpdate = true;
        }
        if (globalValues["nonce"] !== undefined && (globalValuesCache["nonce"] === undefined || !equal(globalValuesCache["nonce"], globalValues["nonce"]))) {
            globalValuesCache["nonce"] = globalValues["nonce"];
            needUpdate = true;
        }
        if (globalValues["counter"] !== undefined && (globalValuesCache["counter"] === undefined || globalValuesCache["counter"] !== globalValues["counter"])) {
            globalValuesCache["counter"] = globalValues["counter"];
            needUpdate = true;
        }
        if (needUpdate) {
            let out = new Uint8Array(chacha20_block(globalValues["key"], globalValues["nonce"], globalValues["counter"]));
            hexprint("chacha20block", out);
        }


        needUpdate = false;
        if (globalValues["keyE"] !== undefined && (globalValuesCache["keyE"] === undefined || !equal(globalValuesCache["keyE"], globalValues["keyE"]))) {
            globalValuesCache["keyE"] = globalValues["keyE"];
            needUpdate = true;
        }
        if (globalValues["nonceE"] !== undefined && (globalValuesCache["nonceE"] === undefined || !equal(globalValuesCache["nonceE"], globalValues["nonceE"]))) {
            globalValuesCache["nonceE"] = globalValues["nonceE"];
            needUpdate = true;
        }
        if (globalValues["counterE"] !== undefined && (globalValuesCache["counterE"] === undefined || globalValuesCache["counterE"] !== globalValues["counterE"])) {
            globalValuesCache["counterE"] = globalValues["counterE"];
            needUpdate = true;
        }
        if (globalValues["plaintext"] !== undefined && (globalValuesCache["plaintext"] === undefined || !equal(globalValuesCache["plaintext"], globalValues["plaintext"]))) {
            globalValuesCache["plaintext"] = globalValues["plaintext"];
            needUpdate = true;
        }
        if (needUpdate) {
            let out = new Uint8Array(chacha20_encrypt(globalValues["keyE"], globalValues["nonceE"], globalValues["counterE"], 64, globalValues["plaintext"]));
            hexprint("chacha20enc", out);
            hexprint("chacha20encinp", globalValues["plaintext"]);
        }


        needUpdate = false;
        if (globalValues["keyP"] !== undefined && (globalValuesCache["keyP"] === undefined || !equal(globalValuesCache["keyP"], globalValues["keyP"]))) {
            globalValuesCache["keyP"] = globalValues["keyP"];
            needUpdate = true;
        }
        if (globalValues["mac"] !== undefined && (globalValuesCache["mac"] === undefined || !equal(globalValuesCache["mac"], globalValues["mac"]))) {
            globalValuesCache["mac"] = globalValues["mac"];
            needUpdate = true;
        }
        if (needUpdate) {
            let out = new Uint8Array(poly1305_mac(globalValues["keyP"], globalValues["mac"]));
            hexprint("poly1305mac", out);
            hexprint("poly1305macinp", globalValues["mac"]);
        }


        needUpdate = false;
        if (globalValues["keyK"] !== undefined && (globalValuesCache["keyK"] === undefined || !equal(globalValuesCache["keyK"], globalValues["keyK"]))) {
            globalValuesCache["keyK"] = globalValues["keyK"];
            needUpdate = true;
        }
        if (globalValues["nonceK"] !== undefined && (globalValuesCache["nonceK"] === undefined || !equal(globalValuesCache["nonceK"], globalValues["nonceK"]))) {
            globalValuesCache["nonceK"] = globalValues["nonceK"];
            needUpdate = true;
        }
        if (needUpdate) {
            let out = new Uint8Array(poly1305_key_gen(globalValues["keyK"], globalValues["nonceK"]));
            hexprint("poly1305key", out);
        }

        needUpdate = false;
        if (globalValues["keyfe"] !== undefined && (globalValuesCache["keyfe"] === undefined || !equal(globalValuesCache["keyfe"], globalValues["keyfe"]))) {
            globalValuesCache["keyfe"] = globalValues["keyfe"];
            needUpdate = true;
        }
        if (globalValues["noncefe"] !== undefined && (globalValuesCache["noncefe"] === undefined || !equal(globalValuesCache["noncefe"], globalValues["noncefe"]))) {
            globalValuesCache["noncefe"] = globalValues["noncefe"];
            needUpdate = true;
        }
        if (globalValues["aadfe"] !== undefined && (globalValuesCache["aadfe"] === undefined || !equal(globalValuesCache["aadfe"], globalValues["aadfe"]))) {
            globalValuesCache["aadfe"] = globalValues["aadfe"];
            needUpdate = true;
        }
        if (globalValuesCache["filefe"] !== fileInputE) {
            globalValuesCache["filefe"] = fileInputE;
            needUpdate = true;
        }
        if (needUpdate) {
            let out = chacha20_aead_encrypt0(globalValues["aadfe"], globalValues["keyfe"], globalValues["noncefe"], fileInputE);
            fileEncryptedCache = out;
            hexprint("tagfe", new Uint8Array(out[0]));
        }

        needUpdate = false;
        if (globalValues["keyfd"] !== undefined && (globalValuesCache["keyfd"] === undefined || !equal(globalValuesCache["keyfd"], globalValues["keyfd"]))) {
            globalValuesCache["keyfd"] = globalValues["keyfd"];
            needUpdate = true;
        }
        if (globalValues["noncefd"] !== undefined && (globalValuesCache["noncefd"] === undefined || !equal(globalValuesCache["noncefd"], globalValues["noncefd"]))) {
            globalValuesCache["noncefd"] = globalValues["noncefd"];
            needUpdate = true;
        }
        if (globalValues["aadfd"] !== undefined && (globalValuesCache["aadfd"] === undefined || !equal(globalValuesCache["aadfd"], globalValues["aadfd"]))) {
            globalValuesCache["aadfd"] = globalValues["aadfd"];
            needUpdate = true;
        }
        if (globalValuesCache["filefd"] !== fileInputD) {
            globalValuesCache["filefd"] = fileInputD;
            needUpdate = true;
        }
        if (globalValuesCache["tagfd"] !== document.getElementById("tagfd").value) {
            globalValuesCache["tagfd"] = document.getElementById("tagfd").value;
            needUpdate = true;
        }
        if (needUpdate) {
            let tagPos = Number(globalValuesCache["tagfd"]);
            let tag = new Uint8Array(16);
            let file = fileInputD;
            if (tagPos === 0 && fileInputD.byteLength >= 16) {
                tag = new Uint8Array(fileInputD.buffer, 0, 16);
                file = new Uint8Array(fileInputD.buffer, 16, fileInputD.byteLength - 16);
            } else if (tagPos === 1 && fileInputD.byteLength >= 16) {
                tag = new Uint8Array(fileInputD.buffer, fileInputD.byteLength - 16, 16);
                file = new Uint8Array(fileInputD.buffer, 0, fileInputD.byteLength - 16);
            }
            let out = chacha20_aead_decrypt(globalValues["aadfd"], globalValues["keyfd"], globalValues["noncefd"], file);
            fileDecryptedCache = out[1];
            hexprint("tagfd0", new Uint8Array(out[0]));
            hexprint("tagfd1", tag);

            let blob = new Blob([fileDecryptedCache]);
            let url = URL.createObjectURL(blob);
            const img = document.getElementById("decimg");
            img.src = url;
            if (prevURL !== undefined) {
                URL.revokeObjectURL(prevURL);
            }
            prevURL = url;
            
        }
    });
};

let prevURL = undefined;


function runAllIntervals() {
    for (let i = 0; i < allIntervals.length; i++) {
        allIntervals[i]();
    }
}
setInterval(runAllIntervals, 50);