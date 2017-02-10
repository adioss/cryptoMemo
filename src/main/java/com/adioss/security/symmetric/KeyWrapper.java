package com.adioss.security.symmetric;

import java.security.Key;
import javax.crypto.*;
import com.adioss.security.Utils;

public class KeyWrapper {
    /**
     * Wrapping allows to mask/encapsulate/protect the key used
     * Create another key, use a cipher with it and {@link Cipher#WRAP_MODE} and wrap the original key
     * To unwrap, use a cipher with {@link Cipher#UNWRAP_MODE}
     */
    static void wrapUnwrapKey() throws Exception {
        // create a key to wrap
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        Key keyToBeWrapped = generator.generateKey();
        System.out.println("input    : " + Utils.toHex(keyToBeWrapped.getEncoded()));

        // create a wrapper and do the wrapping
        Cipher cipher = Cipher.getInstance("AESWrap");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        Key wrapKey = keyGenerator.generateKey();
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        byte[] wrappedKey = cipher.wrap(keyToBeWrapped);
        System.out.println("wrapped : " + Utils.toHex(wrappedKey));

        // unwrap the wrapped key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        System.out.println("unwrapped: " + Utils.toHex(key.getEncoded()));
    }

    public static void main(String[] args) throws Exception {
        wrapUnwrapKey();
    }

    private KeyWrapper() {
    }
}
