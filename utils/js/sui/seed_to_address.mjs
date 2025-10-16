import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import * as bip39 from "bip39";


async function seed_to_address(mnemonic){
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const seedHex = seed.toString("hex");
    const keypair = Ed25519Keypair.deriveKeypairFromSeed(
        seedHex,
        "m/44'/784'/0'/0'/0'");
    const address = keypair.getPublicKey().toSuiAddress();
    return {
        address: address,
    };
}

const mnemonic = process.argv[2];

process.stdout.write(JSON.stringify(await seed_to_address(mnemonic)))
