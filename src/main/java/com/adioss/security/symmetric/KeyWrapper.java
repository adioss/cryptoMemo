package com.adioss.security.symmetric;

import java.security.Key;
import javax.crypto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

class KeyWrapper {
    private static final Logger LOG = LoggerFactory.getLogger(KeyWrapper.class);

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
        LOG.debug("input    : " + Utils.toHex(keyToBeWrapped.getEncoded()));

        // create a wrapper and do the wrapping
        Cipher cipher = Cipher.getInstance("AESWrap");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        Key wrapKey = keyGenerator.generateKey();
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        byte[] wrappedKey = cipher.wrap(keyToBeWrapped);
        LOG.debug("wrapped : " + Utils.toHex(wrappedKey));

        // unwrap the wrapped key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        LOG.debug("unwrapped: " + Utils.toHex(key.getEncoded()));
    }

    private KeyWrapper() {
    }
}
