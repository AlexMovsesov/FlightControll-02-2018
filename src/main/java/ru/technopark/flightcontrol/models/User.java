package ru.technopark.flightcontrol.models;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.codec.binary.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.NONE,
        setterVisibility = JsonAutoDetect.Visibility.NONE,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE
)
public class User implements UserDetails {

    @JsonProperty
    private Number id;

    @JsonProperty
    private String email;

    @JsonProperty
    private String name;

    @JsonProperty
    private int rate = 0;

    @JsonProperty
    private String avatar;

    private String hash;
    private static final Charset CHARSET = StandardCharsets.UTF_8;

    public int getRate() {
        return rate;
    }

    public User(Number id, String email, String login, String pass) {
        this.id = id;
        this.email = email;
        this.name = login;
        changePass(pass);
        //todo: for test purposes, delete it
        this.rate = new Random().nextInt(6);
    }

    public void setAvatar(MultipartFile avatar) throws IOException {
        if (avatar != null && avatar.getSize() > 0) {
            final StringBuilder base64Avatar = new StringBuilder();
            base64Avatar.append("data:");
            base64Avatar.append(avatar.getContentType());
            base64Avatar.append(";base64,");
            base64Avatar.append(
                    StringUtils.newStringUtf8(
                            Base64.encodeBase64(
                                    avatar.getBytes(), false
                            )
                    )
            );
            this.avatar = base64Avatar.toString();
        }
    }

    public String getAvatar() {
        return this.avatar;
    }

    public Number getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void changePass(String pass) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            setHash(digest, pass);
        } catch (NoSuchAlgorithmException exception) {
            hash = "";
        }
    }

    private void setHash(MessageDigest digest, String pass) {
        final byte[] hashed = digest.digest(pass.getBytes(CHARSET));
        hash = new String(hashed);
    }

    public boolean checkHash(String pass) {
        String newHash;
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hashed = digest.digest(pass.getBytes(CHARSET));
            newHash = new String(hashed);
        } catch (NoSuchAlgorithmException exception) {
            newHash = "";
        }
        return this.hash.equals(newHash);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        final Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        final GrantedAuthority grantedAuthority = () -> "ROLE_USER";
        grantedAuthorities.add(grantedAuthority);
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return hash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
