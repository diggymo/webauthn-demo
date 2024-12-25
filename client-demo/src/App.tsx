import { useState } from 'react'
import './App.css'
import * as cbor from 'cbor2';


function App() {
  const [count, setCount] = useState(0)

  return (
   <button onClick={startRegistration}>
    認証登録
   </button>
  )
}

export default App


const enc = new TextEncoder();
const dec = new TextDecoder();

const startRegistration = async () => {
  const res = await window.navigator.credentials.create({
    publicKey: {
      rp: {
        id: "localhost",
        name: 'morimorikochan',
      },
      user: {
        id: enc.encode("9450d86c-0952-49cd-9b59-c057d038e1af"),
        name: 'morifuji',
        displayName: "morifuji-display",
      },
      challenge: enc.encode("8ef3a647-7694-48b3-a087-e90cbc835218"),
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7
        }
      ],
      authenticatorSelection: {
        userVerification: "required",
      }
    },
  })

  console.log({res})

  if (res===null) {
    alert("登録失敗")
    return
  }

  if (!(res instanceof PublicKeyCredential)) {
    console.error({res})
    alert("publicKeyの形式になっていません")
    return
  }

  if (!(res.response instanceof AuthenticatorAttestationResponse)) {
    console.error({res})
    alert("res.responseが想定した形式になっていません")
    return
  }

  const clientExtensionResults = res.getClientExtensionResults()
  const clientJSON = JSON.parse(dec.decode(res.response.clientDataJSON))
  console.log({clientJSON})

  const {fmt, authData, attStmt} = await decodeAttestationObject(res.response.attestationObject)

  console.log(await compareArrayBuffers2(new Uint8Array(authData.buffer), authData))
  console.log("authData", new Uint32Array(authData.buffer.slice(0,32)))
  const rpIdHash = authData.slice(0,32)
  console.log("rpIdHash", rpIdHash)

  const rpId = await crypto.subtle.digest("SHA-256", enc.encode("localhost"))
  console.log("rpId", new Uint8Array(rpId))
  const isMatch = compareArrayBuffers2(new Uint8Array(rpId), rpIdHash)
  console.log({isMatch})

  const flags = authData.slice(32,33)
  console.log("flags", flags)
  console.log("flags:user present", extractBit(flags[0], 0))
  console.log("flags:user verified", extractBit(flags[0], 2))

  const credential = res.getClientExtensionResults()
}



const compareArrayBuffers2 = (buf1: Uint8Array, buf2: Uint8Array) => {
  console.log(buf1.byteLength)

  // バッファの長さが違えば異なる
  if (buf1.byteLength !== buf2.byteLength) {
      return false;
  }

  // バイト単位で比較
  for (let i = 0; i < buf1.length; i++) {
      if (buf1[i] !== buf2[i]) {
          return false;
      }
  }

  return true;
}

type AttestationObjectDecoded = {
  fmt: string;                  // Attestation Statement Format
  authData: Uint8Array;         // Authenticator Data
  attStmt: {
      [key: string]: any;       // フォーマットに応じた内容
  };
};

export const decodeAttestationObject = async(attestationObject: ArrayBuffer):Promise<AttestationObjectDecoded> => {
  // CBORデコード
  const decodedObject = await cbor.decode<AttestationObjectDecoded>(new Uint8Array(attestationObject));

  console.log({decodedObject})
  return decodedObject;
}

/**
 * https://note.kiriukun.com/entry/20190404-extract-a-bit-from-a-byte-in-javascript
 */
const extractBit = (b: number, n: number) => {
  if (b < 0 || 255 < b) {
      throw new RangeError('値は0～255の範囲内で指定してください。');
  }
  if (n < 0 || 7 < n) {
      throw new RangeError('位置は1～8番目の範囲内で指定してください。');
  }
  const c = 8 - n;
  return (b & (1 << c)) >> c;
};