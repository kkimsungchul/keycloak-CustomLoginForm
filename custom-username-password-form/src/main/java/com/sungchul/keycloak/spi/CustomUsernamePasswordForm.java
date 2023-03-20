package com.sungchul.keycloak.spi;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;


public class CustomUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(CustomUsernamePasswordForm.class);

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        boolean timeCheck = transformPassword(context.getSession(),context.getRealm(),formData,context);
        //화면단에 데이터 전송
        //꺼내서 사용할때는  <input type="hidden" id="bb" value ="${(testData!'')}"> 이렇게 사용하면 됨
        //context.form().setAttribute("testData","sample test data");

        //클라이언트와 서버의 시간차이가 5분이상일경우(클라이언트가 5분 더 느릴경우) 오류 처리
        if(!timeCheck){
//            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
//                    context.form().setError("서버와 클라이언트의 시간차이가 5분이상일 경우 로그인이 제한됩니다.","Timestamp is to far in the past").createErrorPage(
//                            Response.Status.INTERNAL_SERVER_ERROR
//                    ));



            Response challengeResponse = challenge(context,"서버와 클라이언트의 시간차이가 5분이상일 경우 로그인이 제한됩니다.", "loginTimeout");
            context.challenge(challengeResponse);

            return;
        }

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            //아래코드 작동안함
            //context.form().setAttribute("testData","testData11");
            System.out.println("로그인 11");
            return;
        }
        if (!validateForm(context, formData)){
            //아래코드 작동안함
            context.form().setAttribute("testData","testData22");
            System.out.println("로그인 22");
            return;
        }
        context.success();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute("usernameHidden", true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH", "true");
        } else {
            context.getAuthenticationSession().removeAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH");
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }

    private boolean transformPassword(KeycloakSession session, RealmModel realm, MultivaluedMap<String, String> formData,AuthenticationFlowContext context) throws IllegalStateException {
        // Get the default active RSA key
        KeyWrapper activeRsaKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        // read Password from input data
        String passwordJWE = formData.getFirst("password");
        JWEObject jweObject = parseJweObject(activeRsaKey, passwordJWE);
        Map<String, Object> jsonObject = jweObject.getPayload().toJSONObject();
        // Validate timestamp, make sure time is not far in the pass.
        boolean timeCheck =validateTimeout(jsonObject,context);
        // Set cleartext password in inputData
        formData.addFirst("password",(String) jsonObject.get("pwd"));
        return timeCheck;
    }

    private boolean validateTimeout(Map<String, Object> jsonObject,AuthenticationFlowContext context) {
        ZonedDateTime dateTime = ZonedDateTime.parse((String) jsonObject.get("timestamp"));
        ZonedDateTime now = ZonedDateTime.now();

        if(true){
        //if (ChronoUnit.MINUTES.between(dateTime, now) > 5) {
            logger.warn("Timestamp is to far in the past.");
            //throw new IllegalStateException("Timestamp is to far in the past.");
            context.form().setAttribute("clientTimeError","clientTimeError");
            return false;
        }

        return true;
    }

    private JWEObject parseJweObject(KeyWrapper activeRsaKey, String passwordJWE) {
        try {
            // Parse JWE
            JWEObject jweObject = JWEObject.parse(passwordJWE);
            // Decrypt password using private key
            jweObject.decrypt(new RSADecrypter((PrivateKey) activeRsaKey.getPrivateKey()));
            return jweObject;
        } catch (ParseException | JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
