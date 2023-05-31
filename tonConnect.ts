import { TonProofItemReplySuccess, CHAIN } from '@tonconnect/protocol';
import { Wallet } from '@tonconnect/sdk';
import * as crypto from 'crypto';
import * as nacl from 'tweetnacl';
import { Address, Cell } from "ton-core";


interface Domain {
  LengthBytes: number // uint32 `json:"lengthBytes"`
  Value: string // string `json:"value"`
}
  
interface ParsedMessage {
  Workchain: number // int32
  Address: Buffer // []byte
  Timstamp: number // int64
  Domain: Domain // Domain
  Signature: Buffer // []byte
  Payload: string // string
  StateInit: string // string
}

const tonProofPrefix = 'ton-proof-item-v2/'
const tonConnectPrefix = 'ton-connect'



const CreateMessage = async (message: ParsedMessage): Promise<Buffer> => {
    const workChain = Buffer.alloc(4)
    workChain.writeUInt32BE(message.Workchain,0)
  
    const timeStamp = Buffer.alloc(8)
    timeStamp.writeBigUInt64LE(BigInt(message.Timstamp))
  
    const domainLength = Buffer.alloc(4)
    domainLength.writeUInt32LE(message.Domain.LengthBytes,0)
  
    const m = Buffer.concat([
      Buffer.from(tonProofPrefix),
      workChain,
      message.Address,
      domainLength,
      Buffer.from(message.Domain.Value),
      timeStamp,
      Buffer.from(message.Payload),
    ])
  
    const messageHash = crypto.createHash('sha256').update(m).digest()
  
    const fullMes = Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from(tonConnectPrefix),
      Buffer.from(messageHash),
    ])
  
    const res = await crypto.createHash('sha256').update(fullMes).digest();
    return Buffer.from(res)
};

const ConvertTonProofMessage = (
    tp: TonProofItemReplySuccess,
    walletInfo: Wallet,
  ): ParsedMessage => {
    const address = Address.parse(walletInfo.account.address);
    
    
    const res: ParsedMessage = {
      Workchain: address.workChain,
      Address: Buffer.from(address.hash),
      Domain: {
        LengthBytes: tp.proof.domain.lengthBytes,
        Value: tp.proof.domain.value,
      },
      Signature: Buffer.from(tp.proof.signature, 'base64'),
      Payload: tp.proof.payload,
      StateInit: walletInfo.account.walletStateInit,
      Timstamp: tp.proof.timestamp,
    }
    return res;
  };

  const verifyTonProof = async (tonProofReply: TonProofItemReplySuccess, wallet: Wallet) => {
    const signatureBase64 = tonProofReply.proof.signature;
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    // Later you can use "wallet.account.address" to associate wallet address with user in DB
    if (wallet.account.chain !== CHAIN.MAINNET) {
      // Don't allow testnet users
      return false;
    }
    if (!wallet.account.publicKey) {
      return false;
    }
    const pubKeyHex = wallet.account.publicKey;
    const pubKeyBuffer = Buffer.from(pubKeyHex, 'hex');
    const parsedMessage = ConvertTonProofMessage(tonProofReply, wallet);
    const messageBuffer = await CreateMessage(parsedMessage);
    const result = SignatureVerify(pubKeyBuffer, messageBuffer, signatureBuffer);
    console.log('Verification result', result);
    return result;
};

const SignatureVerify = (pubkey: Buffer, message: Buffer, signature: Buffer): boolean => {
    return nacl.sign.detached.verify(message, signature, pubkey)
};

const getPublicKey = (receivedStateInit: string, receivedAddress: string) => {
    const cell = Cell.fromBase64(receivedStateInit);

    const hash = cell.hash();
    const encodedHash = hash.toString('hex');
    console.log({hash, receivedAddress, encodedHash});
    if (!receivedAddress.endsWith(encodedHash)) {
      throw new Error("Address does not match hash");
    }
    const publicKey = cell.refs[1].bits.substring(8, 40);
    console.log({ref1: cell.refs[1], publicKe: publicKey.length , bits:  cell.refs[1].bits, publicKeyString: publicKey.toString()})
    return publicKey;
};

const data = {
   
}

const tonConnectAuthenticate = async (context, payload) => {
    const {account, connectItems: {tonProof}} = payload;
    const inputFields = {
        address: account.address,
        chain: account.chain,
        walletStateInit: account.walletStateInit,
        publicKey: account.publicKey,
        proofName: tonProof.name,
        timestamp: tonProof.proof.timestamp, 
        domainLengthBytes: tonProof.proof.domain.lengthBytes,
        domainValue: tonProof.proof.domain.value,
        signature: tonProof.proof.signature, 
        proofPayload: tonProof.proof.payload, 
    }

    console.log({payload});
    const receivedStateInit = payload.account.walletStateInit;
    const receivedAddress = payload.account.address;
    
    const pbKey = getPublicKey(receivedStateInit,receivedAddress);
    console.log({pbKey});

    const isSignatureValid = await verifyTonProof(payload.connectItems.tonProof, payload)
    console.log({isSignatureValid})

    if (!isSignatureValid) {
        throw new Error('Invalir Signature');
    }



   

    
}

export default tonConnectAuthenticate;