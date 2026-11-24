package gov.dot.faa.ang.idms.acmetpm;

import module java.base;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Metadata;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.toolbox.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.dot.faa.ang.idms.acmetpm.acme.IdmsAcmeProvider;
import gov.dot.faa.ang.idms.acmetpm.crypto.TpmProvider;
import gov.dot.faa.ang.idms.acmetpm.webserver.apache.ApacheConfigReader;
import gov.dot.faa.ang.idms.acmetpm.webserver.apache.ApacheHTTPAuthz;

/**
 * Wraps calls to the EJBCA ACME API, leveraging TPM Backed private keys and
 * updating the
 * apache configuration
 *
 * @author robert.sherwood@credentive.com
 */
public class AcmeTpm {
    private static PropLoader props;
    private static String tokenPassword;
    private TpmProvider tpmProvider;
    private URI caUri;
    private Session acmeSession;
    private Account acmeUserAccount;
    private ApacheConfigReader apacheConfig;
    private static String userIdentifier;

    private static final Logger logger = LoggerFactory.getLogger(AcmeTpm.class);

    /**
     * Minimal construct for AcmeTtp. Call initialize() to finish
     * 
     * @throws AcmeTpmException
     */
    public AcmeTpm() throws AcmeTpmException {
        // Set system properties
        // try {
        //     var systemPropStream = AcmeTpm.class.getResourceAsStream("/application.properties");
        //     System.getProperties().load(systemPropStream);
        // } catch (IOException e) {
        //     throw new AcmeTpmException("Unable to load default properties from resource");
        // }

        logger.debug("Loading Properties");
        // Verify the properties file
        props = new PropLoader();

        logger.debug("Loading Token Password");
        tokenPassword = props.getTokenPassword();

        // Set username
        userIdentifier = setUserIdentifier();

        logger.debug("loading Keystore");
        // Load the TPM Keystore
        tpmProvider = new TpmProvider(tokenPassword, props.getProp("token.jcaConfigFile"));

        logger.debug("Loading tracked orders");

    }

    /**
     * Second part of initializer for AcmeTpm. Requires that the User ke and cert
     * are present
     * 
     * @throws AcmeTpmException
     */
    public void initialize() throws AcmeTpmException {
        // Parse the EJBCA URI
        logger.debug("Parsing EJBCA URI from properties");
        try {
            caUri = new URI(props.getProp("ejbca.sessionUri"));
        } catch (URISyntaxException e) {
            throw new AcmeTpmException("Invalid URI provided for CA: " + props.getProp("ejbca.sessionUri"));
        }

        logger.debug("Getting customized IdmsAcmeProvider with tpm SSLContext");
        // Get our customized provider
        AcmeProvider idmsProvider = new IdmsAcmeProvider(getSSLContext());

        logger.debug("Creating the acmeSession");
        // Create the session
        acmeSession = new Session(caUri, idmsProvider);

        logger.debug("Getting the Acme UserAccount");
        // Get the account
        acmeUserAccount = getUserAccount();

        logger.debug("Reading the Apache Configuration");
        // Read the apache configuration
        apacheConfig = new ApacheConfigReader();
    }

    /**
     * Returns a list of virtual Hosts configured in Apache, to help adminsistrators
     * identify the
     * domains to request
     * 
     * @return a Map with a key of the vhost domain, and a value of the
     *         DocumentRoot, Private Key
     *         and Certificate Locations.
     * @throws AcmeTpmException
     */
    public HashMap<String, HashMap<String, String>> listApacheVirtualHosts() throws AcmeTpmException {
        HashMap<String, HashMap<String, String>> apacheVhosts = new HashMap<>();
        for (String vhost : apacheConfig.getHostnames()) {
            HashMap<String, String> vhostConfig = new HashMap<>();
            vhostConfig.put("Document Root", apacheConfig.getDocumentRootforHostname(vhost));
            vhostConfig.put("Private Key Location", apacheConfig.getKeyLocationForHostname(vhost));
            vhostConfig.put("Certificate Location", apacheConfig.getCertLocationForHostname(vhost));
            apacheVhosts.put(vhost, vhostConfig);
        }
        return apacheVhosts;
    }

    /**
     * Get information about outstanding orders, and return the information as
     * strings for processing by the CLI.
     * 
     * @return ArrayList<String> with status information
     * @throws AcmeTpmException
     */
    public ArrayList<String> getOrderInfo() throws AcmeTpmException {
        var infoStrings = new ArrayList<String>();
        var orders = acmeUserAccount.getOrders();
        while (orders.hasNext()) {
            var order = orders.next();
            infoStrings.add("\nOrder hashcode: " + order.hashCode());
            infoStrings.add("Status: " + order.getStatus());
            for (var id : order.getIdentifiers()) {
                infoStrings.add("Order ID: " + id.getValue());
            }
            for (var authorization : order.getAuthorizations()) {
                infoStrings.addAll(getAuthorationInfo(authorization));
            }
        }
        return infoStrings;
    }

    private ArrayList<String> getAuthorationInfo(Authorization authorization) {
        var authorizationInfoStrings = new ArrayList<String>();
        authorizationInfoStrings.add("AUTHORIZATION");
        authorizationInfoStrings.add("Status: " + authorization.getStatus());
        var expiration = authorization.getExpires();
        if (expiration.isPresent()) {
            authorizationInfoStrings.add("Authorization expiration: " + expiration.get());
        }
        authorizationInfoStrings.add("Authorization Identifier: " + authorization.getIdentifier().getValue());
        for (var challenge : authorization.getChallenges()) {
            authorizationInfoStrings.add("CHALLENGE");
            authorizationInfoStrings.add("Status: " + challenge.getStatus());
            var error = challenge.getError();
            if (error.isPresent()) {
                authorizationInfoStrings.add("Errors: " + error.get());
            }
        }
        return authorizationInfoStrings;
    }

    /**
     * Function to test connectivity to the ACME server by accessing the metadata
     * endpoint
     * 
     * @return A HashMap of the metadata key/values
     * @throws AcmeTpmException
     */
    public HashMap<String, String> testAcmeConnection() throws AcmeTpmException {
        HashMap<String, String> metadataProps = new HashMap<>();
        try {
            Metadata acmeMeta = acmeSession.getMetadata();
            JSON metadataJson = acmeMeta.getJSON();
            for (String key : metadataJson.keySet()) {
                metadataProps.put(key, metadataJson.get(key).asString());
            }
            return metadataProps;
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to connect to Acme Server: " + e.getMessage());
        }
    }

    /**
     * Gets or creates the user account
     * 
     * @return
     * @throws AcmeTpmException
     */
    private Account getUserAccount() throws AcmeTpmException {
        // TODO: Not sure this is quite correct - especially the round trip to login
        // and retrieve the account from the URL. Expensive!
        String accountURLProp = props.getProp("acme.accountURL");
        Account userAccount;

        if (accountURLProp == null) {
            String userEmail = props.getProp("acme.userEmail");
            userAccount = requestAcmeAccount(userEmail);
            props.setProp("acme.accountURL", userAccount.getLocation().toString());
        } else {
            try {
                URL accountURL = new URI(accountURLProp).toURL();
                Login login = acmeSession.login(accountURL, tpmProvider.getUserKeyPair());
                return login.getAccount();
            } catch (URISyntaxException | MalformedURLException e) {
                throw new AcmeTpmException("Unable to generate URI from " + accountURLProp);
            }
        }

        return userAccount;
    }

    /**
     * Request user account from Acme Server - if the account already exists, the
     * existing account will be returned.
     * 
     * @param email
     * @return an Account object representing the user account
     * @throws AcmeTpmException
     */
    private Account requestAcmeAccount(String email) throws AcmeTpmException {
        AccountBuilder accountBuilder = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(tpmProvider.getUserKeyPair());

        accountBuilder.addEmail(email);
        try {
            Account account = accountBuilder.create(acmeSession);
            return account;
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to create account: " + e.getMessage());
        }
    }

    /**
     * Get a list of orders from the Acme Server, and process each of them.
     * 
     * @return A list of orders and information about the status of the orders.
     * @throws AcmeTpmException
     */
    public HashMap<String, ArrayList<String>> checkOrders() throws AcmeTpmException {
        logger.debug("Entering checkOrders()");
        var orderStatus = new HashMap<String, ArrayList<String>>();
        try {
            // Account userAccount = getUserAccount();
            var orders = acmeUserAccount.getOrders();
            while (orders.hasNext()) {
                logger.debug("Processing next order...");
                var order = orders.next();
                logger.debug("Order hash: " + order.hashCode());
                var result = processOrder(order);
                for (var id : order.getIdentifiers()) {
                    orderStatus.put(id.getValue(), result);
                }
            }
            return orderStatus;
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Unable to check orders: " + e.getMessage());
        }
    }

    /**
     * Try to determine which keystore alias is associated with an Order
     * 
     * @param order
     * @return
     * @throws AcmeTpmException
     */
    private String findDomainForOrder(Order order) throws AcmeTpmException {
        String domainForOrder = null;

        // Iterate through the order ids to find the alias
        ArrayList<String> orderDomains = new ArrayList<>();
        for (var identifier : order.getIdentifiers()) {
            var orderIdentifer = identifier.getValue();
            orderDomains.add(orderIdentifer);
            if (tpmProvider.hasAlias(orderIdentifer)) {
                domainForOrder = orderIdentifer;
            }
        }

        // If the order is not associated with a managed domain. Throw an exception
        // listing all the domains associated with the order.
        if (domainForOrder == null) {
            StringBuilder sb = new StringBuilder();
            for (var identifier : orderDomains) {
                sb.append(identifier + ", ");
            }
            // trim the final ", " from the end of the sequence.
            sb.delete(sb.length() - 2, sb.length());
            var domainString = sb.toString();
            throw new AcmeTpmException(
                    "Order identifier does not correspond to any managed domain. Identifiers: " + domainString);
        }

        // Otherwise return domainForOrder
        return domainForOrder;
    }

    /**
     * Get the status for an order and call the appropriate function
     * 
     * @param order
     * @return List of strings generated by the functions called from this function.
     * @throws AcmeTpmException
     */
    private ArrayList<String> processOrder(Order order) throws AcmeTpmException {
        logger.debug("Entering processOrder for order {}", order.hashCode());
        logger.debug("Order status: {}", order.getStatus() );
        var statusResults = new ArrayList<String>();
        switch (order.getStatus()) {
            case PENDING:
                // check and fulfill authorizations
                statusResults.add(" ORDER Pending - processing Authorizations");
                statusResults.addAll(processAuthorizations(order.getAuthorizations()));
                break;
            case READY:
                statusResults.add(" ORDER Ready - finalizing.");
                var orderStatus = finalizeOrder(order);
                statusResults.add(orderStatus);
                break;
            case PROCESSING:
                // do nothing. try again later
                statusResults.add(" ORDER Processing - retry later");
                break;
            case VALID:
                // fetch certificate
                statusResults.add(" ORDER Valid - installing certificate");
                getAndInstallCertificate(order);
                break;
            case INVALID:
                // order failed - cancel
                statusResults.add(" ORDER Invalid - check and try again");
                break;
            default:
                throw new AcmeTpmException("Unrecognized order status: " + order.getStatus().toString());
        }
        return statusResults;
    }

    /**
     * Finalize an order
     * 
     * @param order
     * @return
     */
    private String finalizeOrder(Order order) throws AcmeTpmException {
        byte[] domainCSR = null;
        String domain = null;

        // iterate through the identifiers and see if there is a match for a domain
        // under management - note we don't support multi-domain certs yet (TODO)
        var orderIdentifiers = order.getIdentifiers();
        for (var identifier : orderIdentifiers) {
            if (tpmProvider.hasAlias(identifier.getValue())) {
                domain = identifier.getValue();
                domainCSR = tpmProvider.getCertRequestDER(domain, null, false);
            }
        }

        // If we didn't get a match, throw an exception.
        if (domainCSR == null || domain == null) { // redundant checks, but they satisfy the linter.
            throw new AcmeTpmException("Could not find a managed domain associated with the order " + order.toString());
        }

        // Otherwise, attempt to finalize the order.
        try {
            order.execute(domainCSR);
            return ("Finalized order for domain " + domain);
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to place order for " + order.toString());
        }

    }

    /**
     * Retrieve and Install a certificate from a finalized order.
     * 
     * @param order
     * @throws AcmeTpmException
     */
    private ArrayList<String> getAndInstallCertificate(Order order) throws AcmeTpmException {
        logger.debug("Entering getAndInstallCertificate for order {}", order.hashCode());
        
        var statusStrings = new ArrayList<String>();

        // get the domain for the certificate
        try {
            // Find the domain associated with the order
            
            String domain = findDomainForOrder(order);
            statusStrings.add("Fulfilling order for " + domain);
            logger.debug("Fulfilling order for {}", domain);

            // get the certificate from the order
            java.security.cert.X509Certificate certificate = order.getCertificate().getCertificate();
            statusStrings.add("Got certificate " + certificate.getSubjectX500Principal().getName());

            // Update the keystore with the new certificate
            tpmProvider.updateCertificate(domain, certificate);
            statusStrings.add("Updated keystore alias " + domain + " with Certificate");

            // Get the pkcs11 URLs for the keystore alias
            var keyPathMap = tpmProvider.getPkcs11Paths(domain);

            // update the config for vHost
            if (apacheConfig.hostnameExists(domain)) {
                apacheConfig.updateConfigForHostname(domain,
                        keyPathMap.get("SSLCertificateFile"),
                        keyPathMap.get("SSLCertificateKeyFile"));
            }

        } catch (IllegalStateException | AcmeTpmException e) {
            throw new AcmeTpmException("Unable to retrieve and install certificate for " + order.toString() + ":" + e.getMessage());
        }

        return statusStrings;
    }

    /**
     * Retrieve and process authorizations associated with an order in PENDING
     * state.
     * 
     * @param authorizations
     * @return
     * @throws AcmeTpmException
     */
    private ArrayList<String> processAuthorizations(List<Authorization> authorizations) throws AcmeTpmException {
        var authorizationProcessingResults = new ArrayList<String>();
        for (var authorization : authorizations) {
            // See if the authorization has expired
            Instant expiration;
            var optExpiration = authorization.getExpires();
            if (optExpiration.isPresent()) {
                expiration = optExpiration.get();
                if (expiration.isBefore(Instant.now())) {
                    authorizationProcessingResults.add("Authorization expired at " + expiration + ". Cancelling.");
                    authorizationProcessingResults.addAll(cancelAuthorization(authorization));
                    return authorizationProcessingResults;
                }
            }

            // Check the status of the authorization
            switch (authorization.getStatus()) {
                case PENDING:
                    String domain = authorization.getIdentifier().getValue();
                    authorizationProcessingResults.add("  AUTHORIZATION for " + domain);
                    if (apacheConfig.hostnameExists(domain)) {
                        authorizationProcessingResults.addAll(processChallenges(domain, authorization.getChallenges()));
                    } else {
                        authorizationProcessingResults
                                .add("   Could not find vHost for " + domain + ". Skipping authorizaitons.");
                    }

                    break;
                case EXPIRED:
                    // retry order?
                    break;
                case DEACTIVATED:
                    // retry order?
                    break;
                case REVOKED:
                    // retry order?
                    break;
                case INVALID:
                    // retry order?
                    break;
                case VALID:
                    // wait and then end, so that the calling function can retry
                    break;
                default:
                    throw new AcmeTpmException(
                            "Unrecognized authorization status: " + authorization.getStatus().toString());
            }
        }
        return authorizationProcessingResults;
    }

    private ArrayList<String> cancelAuthorization(Authorization authorization) throws AcmeTpmException {
        var cancelAuthorizationResults = new ArrayList<String>();
        try {
            authorization.deactivate();
            cancelAuthorizationResults.add("Successfully cancelled authorization.");
            var cleanupChallengesResults = cleanupChallenges(authorization.getIdentifier().getValue(), authorization.getChallenges());
            cancelAuthorizationResults.addAll(cleanupChallengesResults);
        } catch (AcmeException e) {
            throw new AcmeTpmException("Unable to cancel authorization for order.");
        }
        return cancelAuthorizationResults;
    }

    private ArrayList<String> cleanupChallenges(String domain, List<Challenge> challenges) throws AcmeTpmException {
        var cleanupChallengesResults = new ArrayList<String>();
        for (var challenge : challenges) {
            switch (challenge.getType()) {
                case "http-01":
                    cleanupChallengesResults.add("Deleting challenge file for domain " + domain);
                    var challengeToken = ((Http01Challenge) challenge).getToken();
                    ApacheHTTPAuthz.deleteAuthzFile(Path.of(apacheConfig.getDocumentRootforHostname(domain)),
                            challengeToken);
                    break;
                // Can't process DNS challenges until proxy is completed.
                case "dns-01":
                    // challengeResponses.add(processDnsChallenge(domain, (Dns01Challenge)
                    // challenge));
                    cleanupChallengesResults.add("     J/K we don't do that yet");
                    break;
                default:
                    cleanupChallengesResults
                            .add("     Challenge type " + challenge.getType() + " unrecognized or unimplemented.");
            }
        }
        return cleanupChallengesResults;
    }

    /**
     * Process challenges associated with an authorization in the PENDING state.
     * 
     * @param domain
     * @param challenges
     * @return
     * @throws AcmeTpmException
     */
    private ArrayList<String> processChallenges(String domain, List<Challenge> challenges) throws AcmeTpmException {
        var challengeProcessingResults = new ArrayList<String>();
        for (var challenge : challenges) {
            switch (challenge.getStatus()) {
                case PROCESSING:
                    challengeProcessingResults.add("   CHALLENGE: Status PROCESSING. Will check again on next run.");
                    break;
                case INVALID:
                    challengeProcessingResults
                            .add("   CHALLENGE: Status INVALID. Certificate request will be restarted.");
                    break;
                case VALID:
                    // return to caller, so that the caller can fetch the certificate
                    challengeProcessingResults
                            .add("   CHALLENGE: Status VALID. Certificate will be fetched.");
                    break;
                case PENDING:
                    challengeProcessingResults.add("   CHALLENGE: Status PENDING.");
                    challengeProcessingResults.addAll(processChallenge(domain, challenge));
                    break;
                default:
                    throw new AcmeTpmException("Unrecognized challenge status: " + challenge.getStatus().toString());
            }
        }
        return challengeProcessingResults;

    }

    /**
     * Process an individual challenge
     * 
     * @param domain
     * @param challenge
     * @throws AcmeTpmException
     */
    private ArrayList<String> processChallenge(String domain, Challenge challenge) throws AcmeTpmException {
        ArrayList<String> challengeResponses = new ArrayList<>();
        challengeResponses.add("    CHALLENGE: Processing " + challenge.getType() + " challenge");
        switch (challenge.getType()) {
            case "http-01":
                challengeResponses.addAll(processHttpChallenge(domain, (Http01Challenge) challenge));
                break;
            // Can't process DNS challenges until proxy is completed.
            case "dns-01":
                // challengeResponses.add(processDnsChallenge(domain, (Dns01Challenge)
                // challenge));
                challengeResponses.add("     J/K we don't do that yet");
                break;
            default:
                challengeResponses
                        .add("     Challenge type " + challenge.getType() + " unrecognized or unimplemented.");
        }
        return challengeResponses;
    }

    /**
     * Process a pending HTTP challenge
     * 
     * @param challenge
     * @throws AcmeTpmException
     */
    private ArrayList<String> processHttpChallenge(String domain, Http01Challenge challenge) throws AcmeTpmException {
        ArrayList<String> responseStrings = new ArrayList<>();
        // If we got here, the status is pending and the type is HTTP, so we just need
        // to create the expected file.
        String token = challenge.getToken();
        String authorization = challenge.getAuthorization();

        Path authorizationResourcePath = Path.of(apacheConfig.getDocumentRootforHostname(domain));
        ApacheHTTPAuthz.createAuthzFile(authorizationResourcePath, token, authorization);
        responseStrings.add("     Wrote token file to " + authorizationResourcePath.toString());

        try {
            challenge.trigger();
            responseStrings.add("     Sent notification to server that challenge was processed.");
        } catch (AcmeException e) {
            throw new AcmeTpmException("Error responding to challenge URL:" + e.getMessage());
        }

        return responseStrings;

    }

    /**
     * Process a DNS challenge, and add or update the dnsChallenge list
     * 
     * @param domain
     * @param dnsChallenge
     * @throws AcmeTpmException
     */
    // private String processDnsChallenge(String domain, Dns01Challenge
    // dnsChallenge) throws AcmeTpmException {
    // switch (dnsChallenge.getStatus()) {
    // case PENDING: // Server has not completed the authorization.
    // case PROCESSING: // Validation completed, system processing
    // case VALID: // Authorizations are successful. Finalize the order.
    // // TODO: Define DNS-01 AUTH CHALLENGE RESPONSE
    // return new String("Processed DNS Challenge");
    // case INVALID: // Authorizations Expired. Throw an error
    // throw new AcmeTpmException("Challenge processed, but invalid.");
    // default:
    // throw new AcmeTpmException(
    // "Unrecognized challenge status: " + dnsChallenge.getStatus().toString()
    // );
    // }
    // }

    /**
     * Return true if the key exists, false otherwise
     * @return boolean 
     * @throws AcmeTpmException
     */
    public boolean userKeyExists() throws AcmeTpmException {
        return tpmProvider.hasAlias(props.getProp("token.userAlias"));
    }

    /**
     * Returns information related to the user key
     * 
     * @param domainString
     * @return a hashmap of property names and values.
     * @throws AcmeTpmException
     */
    public HashMap<String, String> getUserKeyInfo() throws AcmeTpmException {
        return tpmProvider.getKeyInfo(props.getProp("token.userAlias"));
    }

    /**
     * Returns information related to keys
     * 
     * @param domainString
     * @return
     * @throws AcmeTpmException
     */
    public HashMap<String, String> getKeyInfo(String domainString) throws AcmeTpmException {
        return tpmProvider.getKeyInfo(domainString);
    }

    /**
     * Generate a username for requests from this host - admin email + hostname
     * @return Calculated username
     * @throws AcmeTpmException
     */
    private String setUserIdentifier() throws AcmeTpmException {
        // get email or throw an exception
        var userEmail = props.getProp("acme.userEmail");
        if (userEmail == null) {
            throw new AcmeTpmException("User Email not set");
        }

        // hostname
        String hostname;
        try {
            hostname = InetAddress.getLocalHost().getCanonicalHostName();
        } catch (UnknownHostException e) {
            throw new AcmeTpmException("Unable to determine server hostname");
        }

        // TODO: Check for existing cert with this name...
        return userEmail + "-" + hostname;
    }

    /**
     * Generates a CSR for the userKeyPair and returns it as a PEM encoded string.
     * 
     * @param keyPairAlias - the alias of the keypair for which to generate the CSR
     * @return PEM encoded String representing the CSR.
     * @throws AcmeTpmException
     */
    public String generateUserCSR() throws AcmeTpmException {
        if (!hasKeyPair(props.getProp("token.userAlias"))) {
            tpmProvider.addAlias(props.getProp("token.userAlias"));
        }


        return tpmProvider.getCertRequestPEM(props.getProp("token.userAlias"), userIdentifier, true);
    }

    /**
     * Updates the certificate associated with the Acme User account
     * 
     * @param certPEM
     * @throws AcmeTpmException
     */
    public void updateUserCert(String certPEM) throws AcmeTpmException {
        tpmProvider.updateCertificatePEM(props.getProp("token.userAlias"), certPEM);
    }

    /**
     * Updates the certificate associated with a domain
     * 
     * @param domain - the domain to be updated
     * @param cert   - the certificate provided by the ACME sever
     * @throws AcmeTpmException
     */
    public void updateDomainCert(String domain, Certificate cert) throws AcmeTpmException {
        tpmProvider.updateCertificate(domain, cert.getCertificate());
    }

    /**
     * Prints information about the keypairs and certificats for one of the domains
     * under management
     * 
     * @param domainString - a string representing a domain, usually a hostname
     * @return keys and information related to the keys
     */
    public HashMap<String, String> getDomainInfo(String domainString) throws AcmeTpmException {
        try {
            if (tpmProvider.hasAlias(domainString)) {
                return tpmProvider.getKeyInfo(domainString);
            } else {
                // return an empty hashmap
                return new HashMap<String, String>();
            }
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException(
                    "Error while attempting to get info for domain " + domainString + ": " + e.getMessage());
        }
    }

    /**
     * Checks for a keypair associated with an alias
     * 
     * @param alias to check for in the TPM keystore
     * @return true if alias exists, false otherwise
     * @throws AcmeTpmException
     */
    public boolean hasKeyPair(String alias) throws AcmeTpmException {
        return tpmProvider.hasAlias(alias);
    }

    /**
     * returns a list of managed domains, which may be an empty list.
     * 
     * @return a list
     */
    public ArrayList<String> listDomains() throws AcmeTpmException {
        try {
            return tpmProvider.getAliases();
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error receieved while trying to list Domains: " + e.getMessage());
        }
    }

    /**
     * Adds a new domain to the managed domain list, generating and storing a key
     * pair.
     * Note that if the domain already exists, nothing changes and the keys are not
     * modified.
     * It initiates an order for a new certificate from the ACME server.
     * 
     * @param domain
     * @throws AcmeTpmException
     */
    public void addDomain(String domain) throws AcmeTpmException {
        try {
            logger.debug("Adding alias for domain " + domain);
            tpmProvider.addAlias(domain);

            // Trick here - when InetAdress parses an IP, the string start with "/",
            // otherwise it doesn't

            // TODO: Distinguish between IP Addresses and DomainNames for purposes of Subject Alternative Name
            var address = InetAddress.getByName(domain);
            if (address.toString().startsWith("/")) {
                logger.debug("Creating order for ip address " + domain);
                Order domainOrder = acmeUserAccount.newOrder().identifier(Identifier.ip(domain)).create();
            } else {
                logger.debug("Creating order for domain " + domain);
                Order domainOrder = acmeUserAccount.newOrder().domain(domain).create();
            }
        } catch (AcmeTpmException | AcmeException | UnknownHostException e) {
            throw new AcmeTpmException("Unable to order certificate for " + domain + ": " + e.getMessage());
        }
    }

    /**
     * Removes a domain from the managed domain list. If the domain does not exist,
     * just return.
     * 
     * @param domain
     * @throws AcmeTpmException
     */
    public void deleteDomain(String domain) throws AcmeTpmException {
        try {
            tpmProvider.deleteAlias(domain);
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error deleting domain: " + e.getMessage());
        }
    }

    /**
     * print a list of domains that will expire before the date provided
     * 
     * @param expirationDate - the expiration date to compare the domain
     *                       certificates against. If not provided, it will be
     *                       looked up in the property file.
     * @return a list of domains that will expire before the date provided, which
     *         may be empty
     */
    public HashMap<String, Date> getExpiringDomains(Date expirationDate) throws AcmeTpmException {
        // if expiration date is not set, set it to the default configured in properties
        try {
            if (expirationDate == null) {
                int renewalLimit = Integer.valueOf(props.getProp("domains.renewalLimit"));
                expirationDate = Date.from(Instant.now().plus(Duration.ofDays(renewalLimit)));
            }
        } catch (NumberFormatException e) {
            throw new AcmeTpmException("Error setting the renewal limit from properties: " + e.getMessage());
        }

        // Populate hashmap with "domain" : certificate expiration date if it is after
        // the passed in date
        var expiringDomainHashMap = new HashMap<String, Date>();
        try {
            var domains = listDomains();
            if (domains.size() > 0) {
                for (var domain : domains) {
                    if (tpmProvider.aliasCertExpiration(domain).after(expirationDate))
                        expiringDomainHashMap.put(domain, expirationDate);
                }
            }
            return expiringDomainHashMap;
        } catch (AcmeTpmException e) {
            throw new AcmeTpmException("Error getting expiration dates from TPM backed token: " + e.getMessage());
        }

    }

    /**
     * Returns an SSLContext from the tpmProvider. Used for client authenticated SSL
     * connections to the ACME server
     * 
     * @return an SSL context which will leverage the TPM backed keys.
     * @throws AcmeTpmException if the SSL Context cannot be created
     */
    public SSLContext getSSLContext() throws AcmeTpmException {
        return tpmProvider.getSSLContext(Path.of(props.getProp("token.truststore")));
    }
}
