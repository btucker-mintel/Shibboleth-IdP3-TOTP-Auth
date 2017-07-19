package net.kvak.shibboleth.totpauth.authn.impl.seed;

import java.util.ArrayList;
import java.util.List;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.filter.EqualsFilter;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext.AuthState;

@SuppressWarnings("deprecation")
public class LdapSeedFetcher implements SeedFetcher {

	/* Class logger */
	private final Logger log = LoggerFactory.getLogger(LdapSeedFetcher.class);

	/* LdapTemplate */
	private LdapTemplate ldapTemplate;

	/* seedToken attribute in ldap */
	private String seedAttribute;

	/* Username attribute in ldap */
	private String userAttribute;

    /* FilePath to decryption key */
    private String keyPath = null;

	public void setLdapTemplate(LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	public void setKeyPath(String keyPath) {
		this.keyPath = keyPath;
	}

	public LdapSeedFetcher(String seedAttribute, String userAttribute) {
		log.debug("Construct LdapSeedFetcher with {} - {}", seedAttribute, userAttribute);
		this.seedAttribute = seedAttribute;
		this.userAttribute = userAttribute;
	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx) {
		log.debug("Entering LdapSeedFetcher");

		try {
			ArrayList<String> list = getAllTokenCodes(username);
			if (list.isEmpty() || list.get(0) == null) {
                tokenUserCtx.setState(AuthState.REGISTER);
                log.debug("List with token seeds was empty");
			} else {
                log.debug("Token seed list size is: {} first: {}", list.size(), list.get(0));

                for (String seed : list) {
                    log.debug("Adding seed {} for user {}", seed, username);
                    tokenUserCtx.setTokenSeed(seed);
                }
                tokenUserCtx.setState(AuthState.OK);
			}
		} catch (Exception e) {
			tokenUserCtx.setState(AuthState.MISSING_SEED);
			log.error("Encountered problems with LDAP", e);
		}

	}

    public PrivateKey getKey() {
        log.debug("Extracting private key from file");
        try {
            byte[] allBytes = Files.readAllBytes(new File(this.keyPath).toPath());
            String rawKey = new String(allBytes, "UTF-8");
            rawKey = rawKey.replace("-----BEGIN PRIVATE KEY-----", "");
            rawKey = rawKey.replace("-----END PRIVATE KEY-----", "");
            rawKey = rawKey.replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(rawKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            log.debug("Private key extracted");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            log.error("Error with getKey", e);
        }
        log.error("No private key found");
        return null;
    }

	public ArrayList<String> getAllTokenCodes(String user) {
		log.debug("Entering getAllTokenCodes");
		ArrayList<String> tokenList = new ArrayList<String>();

		try {
            Cipher cipher = Cipher.getInstance("RSA");
            PrivateKey key = null;
            if (this.keyPath != null) {
                key = getKey();
                cipher.init(Cipher.DECRYPT_MODE, key);
            }

			DirContextOperations context = ldapTemplate.lookupContext(fetchDn(user));
			String[] values = context.getStringAttributes(seedAttribute);

			if (values.length > 0) {
				for (String value : values) {
                    String token;
                    if (key != null) {
                        try {
                            token = new String(cipher.doFinal(Base64.getDecoder().decode(value)), "UTF-8");
                            token = token.replaceAll("\\s","").replaceAll("\n","").replaceAll("\r","");
                        } catch (Exception e) {
                            token = value;
                        }
                    } else {
                        token = value;
                    }
					tokenList.add(token);
				}
			}

		} catch (Exception e) {
			log.error("Error with getAllTokenCodes", e);
		}

		return tokenList;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private String fetchDn(String userName) {

		String dn = "";
		EqualsFilter filter = new EqualsFilter(userAttribute, userName);
		log.debug("{} Trying to find user {} dn from ldap with filter {}", userName, filter.encode());

		List result = ldapTemplate.search(DistinguishedName.EMPTY_PATH, filter.toString(), new AbstractContextMapper() {
			protected Object doMapFromContext(DirContextOperations ctx) {
				return ctx.getDn().toString();
			}
		});
		if (result.size() == 1) {
			log.debug("User {} relative DN is: {}", userName, (String) result.get(0));
			dn = (String) result.get(0);
		} else {
			log.debug("{} User not found or not unique. DN size: {}", result.size());
			throw new RuntimeException("User not found or not unique");
		}

		return dn;
	}
}
