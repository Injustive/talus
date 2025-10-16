import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import * as bip39 from "bip39";


async function signSuiMessage(mnemonic, message) {
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const seedHex = seed.toString("hex");
    const keypair = Ed25519Keypair.deriveKeypairFromSeed(
        seedHex,
        "m/44'/784'/0'/0'/0'"
    );
    const bytes = new TextEncoder().encode(message);
    const { signature, bytes: committedBytes } = await keypair.signPersonalMessage(bytes);
    return signature
}

async function sign_message(mnemonic, message){
    return await signSuiMessage(mnemonic, message)
}

const mnemonic = process.argv[2];
const message = process.argv[3];

process.stdout.write(JSON.stringify(await sign_message(mnemonic, message)))
