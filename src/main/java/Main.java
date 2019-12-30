import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;
import io.github.novacrypto.bip44.Account;
import io.github.novacrypto.bip44.AddressIndex;
import io.github.novacrypto.bip44.Change;

import java.security.SecureRandom;

import static io.github.novacrypto.bip32.Index.hard;
import static io.github.novacrypto.bip44.BIP44.m;

public final class Main {

    public static void main(String[] args) {
        final String mnemonic = generateNewMnemonic(Words.TWELVE);
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        System.out.println("mnemonic = " + mnemonic + " || seed = " + seed.length);
        for (int i = 0; i < seed.length;i ++ ){
            System.out.print(seed[i]);
        }
        System.out.println("\n=========");
        ExtendedPrivateKey root = ExtendedPrivateKey.fromSeed(seed, Bitcoin.MAIN_NET);

//        String addressMethod1 = root
//                .cKDpriv(hard(44)) //fixed
//                .cKDpriv(hard(0)) //bitcoin testnet coin
//                .cKDpriv(hard(0)) //account =1
//                .cKDpriv(0) //external
//                .cKDpriv(0) //first address
//                .neuter().p2pkhAddress();
//
//        String addressMethod2 = root
//                .cKDpriv(hard(44)) //fixed
//                .cKDpriv(hard(0)) //bitcoin testnet coin
//                .cKDpriv(hard(0)) //account =1
//                .neuter() //switch to public keys
//                .cKDpub(0) //external
//                .cKDpub(0) //first address
//                .p2pkhAddress();

        String addressMethod3 = root
                .derive("m/0/0")
                .neuter().p2pkhAddress();

//        System.out.println(addressMethod1);
//        System.out.println(addressMethod2);
        System.out.println("BIP32 m/0/0 = " + addressMethod3);
        System.out.println("========");
//        String path = m().purpose44()
//                .coinType(0)
//                .account(0)
//                .external()
//                .toString(); //"m/44'/2'/1'/0/5"
//        System.out.println(path);

        AddressIndex addressIndex = m()
                .purpose44()
                .coinType(0)
                .account(0)
                .external()
                .address(0);

        String addressMethod4 = root.derive(
                addressIndex,
                AddressIndex.DERIVATION
        )
                .neuter()
                .p2pkhAddress();
        System.out.println("BIP44 m/44'/0'/0'/0/0 => " + addressMethod4);

        System.out.println("========");

        final Account account =
                m().purpose44()
                        .coinType(0)
                        .account(0);
        final ExtendedPublicKey accountKey = root.derive(
                account,
                Account.DERIVATION
        ).neuter();

        final Change external = account.external();

        for (int i = 0; i < 20; i++) {
            final AddressIndex derivationPath = external.address(i);
            final ExtendedPublicKey publicKey =
                    accountKey.derive(
                            derivationPath,
                            AddressIndex.DERIVATION_FROM_ACCOUNT
                    );
            System.out.println(
                    derivationPath + " = " + publicKey.p2pkhAddress()
            );
        }

//        AddressIndex addressIndex = m()
//                .purpose44()
//                .coinType(1)
//                .account(0)
//                .external()
//                .address(0);
//        String addressMethod4 = root.derive(
//                addressIndex,
//                AddressIndex.DERIVATION
//        )
//                .neuter()
//                .p2pkhAddress();
    }

    private static String generateNewMnemonic(Words wordCount) {
        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[wordCount.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE)
                .createMnemonic(entropy, sb::append);
        return sb.toString();
    }
}
