package net.kvak.shibboleth.totpauth.authn.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;

import com.google.common.base.Function;

@SuppressWarnings("rawtypes")
public class GenerateNewToken extends AbstractProfileAction {

	/** Class logger. */
	@Nonnull
	private final Logger log = LoggerFactory.getLogger(GenerateNewToken.class);

	TokenUserContext tokenCtx;

	/** Lookup strategy for username to match against Token identity. */
	@Nonnull private Function<ProfileRequestContext,String> usernameLookupStrategy;

	/** Attempted username. */
	@Nullable @NotEmpty private String username;

	/** Google Authenticator **/
	@Nonnull
	@NotEmpty
	private GoogleAuthenticator gAuth;

	/** Issuer name for Authenticator **/
	@Nonnull
	@NotEmpty
	private String gAuthIssuerName;


	/** Constructor **/
	public GenerateNewToken() {
		super();
		usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
	}


	/** Inject token authenticator **/
	public void setgAuth(@Nonnull @NotEmpty final GoogleAuthenticator gAuth) {
		this.gAuth = gAuth;
	}

	public void setgAuthIssuerName(@Nonnull @NotEmpty final String gAuthIssuerName) {
		this.gAuthIssuerName = gAuthIssuerName;
	}

	@Override
	protected void doInitialize() throws ComponentInitializationException {
	    super.doInitialize();
	}

	@Override
	protected boolean doPreExecute(ProfileRequestContext profileRequestContext) {
		log.debug("Entering GenerateNewToken doPreExecute");

		try {
			tokenCtx = profileRequestContext.getSubcontext(AuthenticationContext.class)
					.getSubcontext(TokenUserContext.class, true);
			username = usernameLookupStrategy.apply(profileRequestContext);
			return true;
		} catch (Exception e) {
			log.debug("Error with doPreExecute", e);
			return false;

		}

	}

    @Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
    	log.debug("Entering GenerateNewToken doExecute");

		try {
			log.debug("Trying to create new token for {}", username);
			generateToken();
		} catch (Exception e) {
			log.debug("Failed to create new token", e);
		}

	}

	private void generateToken() {
		log.debug("Generating new token shared secret and URL for {}", username);

		try {
			final GoogleAuthenticatorKey key = gAuth.createCredentials();

			String totpUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(gAuthIssuerName, username, key);
			log.debug("Totp URL for {} is {}", username, totpUrl);
			tokenCtx.setTotpUrl(totpUrl);

			String sharedSecret = StringSupport.trimOrNull(key.getKey());
			log.debug("Shared secret for {} is {}", username, sharedSecret);
			tokenCtx.setSharedSecret(sharedSecret);

		} catch (Exception e) {
			log.debug("Error generating new token",e);
		}



	}

}
