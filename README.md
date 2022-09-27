# keycloak-encryption-provider

A keycloak password encryption provider.

Encrypt the password by the realm default RSA public key when login.

## Development

Build the java project, copy `keycloak-password-provider.jar` to KEYCLOAK_HOME/standalone/deployments.

```shell
cd password-encryption-provider
./gradlew shadowJar
```

Build the js project, copy `dist/password-encryption-provider.js` to KEYCLOAK_HOME/themes/base/login/resources/js/.

```shell
cd password-encryption-provider-js
npm ci && npm run build
```

Add `scripts=js/password-encryption-provider.js` to the file
`KEYCLOAK_HOME/themes/base/login/theme.properties`, to make sure the keycloak will load the js file when login.

By default, the KEYCLOAK_HOME is /opt/jboss/keycloak.

## Usage

Git clone the source, build java and js, and rebuild the keycloak images by yourself.

Or pull the docker image `nxest/keycloak-encryption-provider`, add a init container to your keycloak helm charts, copy the release files to the keycloak home.

## Compatibility

| Release | Keycloak Version |
| ------- | ---------------- |
| 1.x.x   | 10.x/11.x/12.x   |

## License

Licensed under Apache 2.0. Copyright (c) 2021 [nxest.com](https://nxest.com)


---------------------------------------------------------------------------------------------------
원본파일  :https://github.com/l10178/keycloak-encryption-provider

나는 해당소스를 내려받아서 usernamePasswordForm 로 구현을 하였음.
암호화 알고리즘 자체를 다시 구현하려면 또 찾아봐야되고 하니까 일단 저기에 있는 소스를 받아서 사용함