package com.rhy.security;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2019/12/28 19:05
 * @Modified By:
 * @Version: 1.0.0
 */
@Component
public class PasswordEncoderImpl implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        String rawPasswordMd5 = rawPassword.toString();
        String res = DigestUtils.md5Hex(rawPasswordMd5);
        return res;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        String rawPasswordStr = rawPassword.toString();
        String rawPasswordMd5 = encode(rawPasswordStr);
        boolean res =encodedPassword.equals(rawPasswordMd5);
        return res;
    }
}
