package net.kvak.shibboleth.totpauth.authn.impl;

import java.util.ArrayList;
import java.util.Iterator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.TokenValidator;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext.AuthState;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;

import com.google.common.base.Function;

/**
 * Validates users TOTP token code against injected authenticator
 *
 * An action that checks for a {@link TokenCodeContext} and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on submitted
 * tokencode and username
 *
 * @author korteke
 *
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
public class TotpTokenValidator extends AbstractValidationAction implements TokenValidator {

	/** Class logger. */
	@Nonnull
	@NotEmpty
	private final Logger log = LoggerFactory.getLogger(TotpTokenValidator.class);

	/** Google Authenticator **/
	@Nonnull
	@NotEmpty
	private GoogleAuthenticator gAuth;

  /** Lookup strategy for username to match against Token identity. */
  @Nonnull private Function<ProfileRequestContext,String> usernameLookupStrategy;

  /** Attempted username. */
  @Nullable @NotEmpty private String username;

	/** Injected seedFetcher **/
	@Nonnull
	@NotEmpty
	private SeedFetcher seedFetcher;

	private boolean result = false;

	/** Inject seedfetcher **/
	public void setseedFetcher(@Nonnull @NotEmpty final SeedFetcher seedFetcher) {
		this.seedFetcher = seedFetcher;
	}

	/** Inject token authenticator **/
	public void setgAuth(@Nonnull @NotEmpty final GoogleAuthenticator gAuth) {
		this.gAuth = gAuth;
	}

	/** Constructor **/
	public TotpTokenValidator() {
		super();
    usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
	}

	@Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
			@Nonnull final AuthenticationContext authenticationContext) {
		log.debug("{} Entering totpvalidator", getLogPrefix());

		try {

			TokenUserContext tokenCtx = authenticationContext.getSubcontext(TokenUserContext.class, true);
			username = usernameLookupStrategy.apply(profileRequestContext);

			/* Add seeds from repository to tokenUserContext */
			seedFetcher.getSeed(username, tokenCtx);

			if (tokenCtx.getState() == AuthState.OK) {
				log.debug("{} Validating user token against seed", getLogPrefix());

				/* Get seeds from tokenUserContext */
				ArrayList<String> seeds = tokenCtx.getTokenSeed();

				/* Iterate over seeds and try to validate them */
				Iterator<String> it = seeds.iterator();
				while (it.hasNext()) {
					result = validateToken(it.next(), tokenCtx.getTokenCode());
					if (result) {
						log.info("{} Token authentication success for user: {}", getLogPrefix(), username);
						tokenCtx.setState(AuthState.OK);
						buildAuthenticationResult(profileRequestContext, authenticationContext);
						return;
					}
				}
			}

			if (tokenCtx.getState() == AuthState.REGISTER) {
				log.info("{} User: {} has not registered token", getLogPrefix(), username);
				handleError(profileRequestContext, authenticationContext, "RegisterToken",
						AuthnEventIds.ACCOUNT_ERROR);
				return;
			}

			if (!result) {
				log.info("{} Token authentication failed for user: {}", getLogPrefix(), username);
				tokenCtx.setState(AuthState.CANT_VALIDATE);
				handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
						AuthnEventIds.INVALID_CREDENTIALS);
				return;
			}

		} catch (Exception e) {
			log.warn("{} Login by {} produced exception", getLogPrefix(), username, e);
			handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
					AuthnEventIds.INVALID_CREDENTIALS);
		}

	}

	@Override
	public boolean validateToken(String seed, int token) {
		log.debug("{} Entering validatetoken", getLogPrefix());

		if (seed.length() == 16) {
			log.debug("{} authorize {} - {} ", getLogPrefix(), seed, token);
			return gAuth.authorize(seed, token);
		}
		log.debug("{} Token code validation failed. Seed is not 16 char long", getLogPrefix());
		return false;
	}

	@Override
	protected Subject populateSubject(Subject subject) {
		if (StringSupport.trimOrNull(username) != null) {
			log.debug("{} Populate subject {}", getLogPrefix(), username);
			subject.getPrincipals().add(new UsernamePrincipal(username));
			return subject;
		}
		return null;

	}

}
