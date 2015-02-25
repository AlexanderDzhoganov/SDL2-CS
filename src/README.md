# Email address as a User ID

Many sites use email addresses as a user id, which is a good mechanism for ensuring a unique identifier for each user without adding the burden of remembering a new username. However, many web applications do not treat email addresses correctly due to common misconceptions about what constitutes a valid address.

Specifically, it is completely valid to have an mailbox address which:
* Is case sensitive in the local-part
* Has non-alphanumeric characters in the local-part (including + and @)
* Has zero or more labels (though zero is admittedly not going to occur)

Following RFC 5321, best practice for validating an email address would be to:

* Check for presence of at least one @ symbol in the address
* Ensure the local-part is no longer than 64 octets
* Ensure the domain is no longer than 255 octets
* Ensure the address is deliverable. To ensure an address is deliverable, the only way to check this is to send the user an email and have the user take action to confirm receipt. Beyond confirming that the email address is valid and deliverable, this also provides a positive acknowledgement that the user has access to the mailbox and is likely to be authorised to use it.

# Password Complexity
Applications should enforce password complexity rules to discourage easy to guess passwords. Password mechanisms should allow virtually any character the user can type to be part of their password, including the space character. Passwords should, obviously, be case sensitive in order to increase their complexity. Occasionally, we find systems where passwords aren't case sensitive, frequently due to legacy system issues like old mainframes that didn't have case sensitive passwords.

The password change mechanism should require a minimum level of complexity that makes sense for the application and its user population. For example:

Password must meet at least 3 out of the following 4 complexity rules
* at least 1 uppercase character (A-Z)
* at least 1 lowercase character (a-z)
* at least 1 digit (0-9)
* at least 1 special character (punctuation) — do not forget to treat space as special characters too
* at least 10 characters
* at most 128 characters
* not more than 2 identical characters in a row (e.g., 111 not allowed)

As application's require more complex password policies, they need to be very clear about what these policies are.

The required policy needs to be explicitly stated on the password change page
be sure to list every special character you allow, so it's obvious to the user
Recommendation:

Ideally, the application would indicate to the user as they type in their new password how much of the complexity policy their new password meets
In fact, the submit button should be grayed out until the new password meets the complexity policy and the 2nd copy of the new password matches the 1st. This will make it far easier for the user to understand and comply with your complexity policy.

Regardless of how the UI behaves, when a user submits their password change request:
* If the new password doesn't comply with the complexity policy, the error message should describe EVERY complexity rule that the new password does not comply with, not just the 1st rule it doesn't comply with

Changing passwords should be EASY, not a hunt in the dark.

# Secure Password Recovery Mechanism

## The Problem
There is no industry standard for implementing a Forgot Password feature. The result is that you see applications forcing users to jump through myriad hoops involving emails, special URLs, temporary passwords, personal security questions, and so on. With some applications you can recover your existing password. In others you have to reset it to a new value.

## Step 1) Gather Identity Data or Security Questions
The first page of a secure Forgot Password feature asks the user for multiple pieces of hard data that should have been previously collected (generally when the user first registers). Steps for this are detailed in the identity section the Choosing and Using Security Questions Cheat Sheet here.

At a minimum, you should have collected some data that will allow you to send the password reset information to some out-of-band side-channel, such as a (possibly different) email address or an SMS text number, etc. to be used in Step 3.

## Step 2) Verify Security Questions
After the form on Step 1 is submitted, the application verifies that each piece of data is correct for the given username. If anything is incorrect, or if the username is not recognized, the second page displays a generic error message such as “Sorry, invalid data”. If all submitted data is correct, Step 2 should display at least two of the user’s pre-established personal security questions, along with input fields for the answers. It’s important that the answer fields are part of a single HTML form.

Do not provide a drop-down list for the user to select the questions he wants to answer. Avoid sending the username as a parameter (hidden or otherwise) when the form on this page is submitted. The username should be stored in the server-side session where it can be retrieved as needed.

Because users' security questions / answers generally contains much less entropy than a well-chosen password (how many likely answers are there to the typical "What's your favorite sports team?" or "In what city where you born?" security questions anyway?), make sure you limit the number of guesses attempted and if some threshold is exceeded for that user (say 3 to 5), lock out the user's account for some reasonable duration (say at least 5 minutes) and then challenge the user with some form of challenge token per standard multi-factor workflow; see #3, below) to mitigate attempts by hackers to guess the questions and reset the user's password. (It is not unreasonable to think that a user's email account may have already been compromised, so tokens that do not involve email, such as SMS or a mobile soft-token, are best.)

## Step 3) Send a Token Over a Side-Channel
After step 2, lock out the user's account immediately. Then SMS or utilize some other multi-factor token challenge with a randomly-generated code having 8 or more characters. This introduces an “out-of-band” communication channel and adds defense-in-depth as it is another barrier for a hacker to overcome. If the bad guy has somehow managed to successfully get past steps 1 and 2, he is unlikely to have compromised the side-channel. It is also a good idea to have the random code which your system generates to only have a limited validity period, say no more than 20 minutes or so. That way if the user doesn't get around to checking their email and their email account is later compromised, the random token used to reset the password would no longer be valid if the user never reset their password and the "reset password" token was discovered by an attacker. Of course, by all means, once a user's password has been reset, the randomly-generated token should no longer be valid.

## Step 4) Allow user to change password in the existing session
Step 4 requires input of the code sent in step 3 in the existing session where the challenge questions were answered in step 2, and allows the user to reset his password. Display a simple HTML form with one input field for the code, one for the new password, and one to confirm the new password. Verify the correct code is provided and be sure to enforce all password complexity requirements that exist in other areas of the application. As before, avoid sending the username as a parameter when the form is submitted. Finally, it's critical to have a check to prevent a user from accessing this last step without first completing steps 1 and 2 correctly. Otherwise, a forced browsing attack may be possible.

# Store Passwords in a Secure Fashion

## Do not limit the character set and set long max lengths for credentials
Some organizations restrict the 1) types of special characters and 2) length of credentials accepted by systems because of their inability to prevent SQL Injection, Cross-site scripting, command-injection and other forms of injection attacks. These restrictions, while well-intentioned, facilitate certain simple attacks such as brute force.

Do not apply short or no length, character set, or encoding restrictions on the entry or storage of credentials. Continue applying encoding, escaping, masking, outright omission, and other best practices to eliminate injection risks.

A reasonable long password length is 160. Very long password policies can lead to DOS in certain circumstances[1].

## Use a cryptographically strong credential-specific salt
A salt is fixed-length cryptographically-strong random value. Append credential data to the salt and use this as input to a protective function. Store the protected form appended to the salt as follows:

[protected form] = [salt] + protect([protection func], [salt] + [credential]);

Follow these practices to properly implement credential-specific salts:

Generate a unique salt upon creation of each stored credential (not just per user or system wide);
Use cryptographically-strong random [*3] data;
As storage permits, use a 32bit or 64b salt (actual size dependent on protection function);
Scheme security does not depend on hiding, splitting, or otherwise obscuring the salt.
Salts serve two purposes: 1) prevent the protected form from revealing two identical credentials and 2) augment entropy fed to protecting function without relying on credential complexity. The second aims to make pre-computed lookup attacks [*2] on an individual credential and time-based attacks on a population intractable.

## Impose infeasible verification on attacker
The function used to protect stored credentials should balance attacker and defender verification. The defender needs an acceptable response time for verification of users’ credentials during peak use. However, the time required to map <credential> → <protected form> must remain beyond threats’ hardware (GPU, FPGA) and technique (dictionary-based, brute force, etc) capabilities.

Two approaches facilitate this, each imperfectly.

## Leverage an adaptive one-way function
Adaptive one-way functions compute a one-way (irreversible) transform. Each function allows configuration of ‘work factor’. Underlying mechanisms used to achieve irreversibility and govern work factors (such as time, space, and parallelism) vary between functions and remain unimportant to this discussion.

Select:

PBKDF2 [*4] when FIPS certification or enterprise support on many platforms is required;
scrypt [*5] where resisting any/all hardware accelerated attacks is necessary but support isn’t.
bcrypt where PBKDF2 or scrypt support is not available.
Example protect() pseudo-code follows:

return [salt] + pbkdf2([salt], [credential], c=10000);

Designers select one-way adaptive functions to implement protect() because these functions can be configured to cost (linearly or exponentially) more than a hash function to execute. Defenders adjust work factor to keep pace with threats’ increasing hardware capabilities. Those implementing adaptive one-way functions must tune work factors so as to impede attackers while providing acceptable user experience and scale.

Additionally, adaptive one-way functions do not effectively prevent reversal of common dictionary-based credentials (users with password ‘password’) regardless of user population size or salt usage.

## Work Factor
Since resources are normally considered limited, a common rule of thumb for tuning the work factor (or cost) is to make protect() run as slow as possible without affecting the users' experience and without increasing the need for extra hardware over budget. So, if the registration and authentication's cases accept protect() taking up to 1 second, you can tune the cost so that it takes 1 second to run on your hardware. This way, it shouldn't be so slow that your users become affected, but it should also affect the attackers' attempt as much as possible.

While there is a minimum number of iterations recommended to ensure data safety, this value changes every year as technology improves. An example of the iteration count chosen by a well known company is the 10,000 iterations Apple uses for its iTunes passwords (using PBKDF2)[2](PDF file). However, it is critical to understand that a single work factor does not fit all designs. Experimentation is important.[*6]

## Leverage Keyed functions
Keyed functions, such as HMACs, compute a one-way (irreversible) transform using a private key and given input. For example, HMACs inherit properties of hash functions including their speed, allowing for near instant verification. Key size imposes infeasible size- and/or space- requirements on compromise--even for common credentials (aka password = ‘password’). Designers protecting stored credentials with keyed functions:

Use a single “site-wide” key;
Protect this key as any private key using best practices;
Store the key outside the credential store (aka: not in the database);
Generate the key using cryptographically-strong pseudo-random data;
Do not worry about output block size (i.e. SHA-256 vs. SHA-512).
Example protect() pseudo-code follows:

return [salt] + HMAC-SHA-256([key], [salt] + [credential]);

Upholding security improvement over (solely) salted schemes relies on proper key management.

## Design password storage assuming eventual compromise
The frequency and ease with which threats steal protected credentials demands “design for failure”. Having detected theft, a credential storage scheme must support continued operation by marking credential data compromised and engaging alternative credential validation workflows as follows:

## Protect the user’s account
- Invalidate authentication ‘shortcuts’ disallowing login without 2nd factors or secret questions.
- Disallow changes to user accounts such as editing secret questions and changing account multi-factor configuration settings.
- Load and use new protection scheme
- Load a new (stronger) protect(credential) function
- Include version information stored with form
- Set ‘tainted’/‘compromised’ bit until user resets credentials
- Rotate any keys and/or adjust protection function parameters (iter count)
- Increment scheme version number
- When user logs in:
- Validate credentials based on stored version (old or new); if old demand 2nd factor or secret answers
- Prompt user for credential change, apologize, & conduct out-of-band confirmation
- Convert stored credentials to new scheme as user successfully log in

# Transmit Passwords Only Over TLS

## Architectural Decision
An architectural decision must be made to determine the appropriate method to protect data when it is being transmitted. The most common options available to corporations are Virtual Private Networks (VPN) or a SSL/TLS model commonly used by web applications. The selected model is determined by the business needs of the particular organization. For example, a VPN connection may be the best design for a partnership between two companies that includes mutual access to a shared server over a variety of protocols. Conversely, an Internet facing enterprise web application would likely be best served by a SSL/TLS model.

This cheat sheet will focus on security considerations when the SSL/TLS model is selected. This is a frequently used model for publicly accessible web applications.

# Providing Transport Layer Protection with SSL/TLS

## Benefits
The primary benefit of transport layer security is the protection of web application data from unauthorized disclosure and modification when it is transmitted between clients (web browsers) and the web application server, and between the web application server and back end and other non-browser based enterprise components.

The server validation component of TLS provides authentication of the server to the client. If configured to require client side certificates, TLS can also play a role in client authentication to the server. However, in practice client side certificates are not often used in lieu of username and password based authentication models for clients.

TLS also provides two additional benefits that are commonly overlooked; integrity guarantees and replay prevention. A TLS stream of communication contains built-in controls to prevent tampering with any portion of the encrypted data. In addition, controls are also built-in to prevent a captured stream of TLS data from being replayed at a later time.

It should be noted that TLS provides the above guarantees to data during transmission. TLS does not offer any of these security benefits to data that is at rest. Therefore appropriate security controls must be added to protect data while at rest within the application or within data stores.

## Basic Requirements
The basic requirements for using TLS are: access to a Public Key Infrastructure (PKI) in order to obtain certificates, access to a directory or an Online Certificate Status Protocol (OCSP) responder in order to check certificate revocation status, and agreement/ability to support a minimum configuration of protocol versions and protocol options for each version.

## SSL vs. TLS
The terms, Secure Socket Layer (SSL) and Transport Layer Security (TLS) are often used interchangeably. In fact, SSL v3.1 is equivalent to TLS v1.0. However, different versions of SSL and TLS are supported by modern web browsers and by most modern web frameworks and platforms. For the purposes of this cheat sheet we will refer to the technology generically as TLS. Recommendations regarding the use of SSL and TLS protocols, as well as browser support for TLS, can be found in the rule below titled "Only Support Strong Protocols".

## When to Use a FIPS 140-2 Validated Cryptomodule
If the web application may be the target of determined attackers (a common threat model for Internet accessible applications handling sensitive data), it is strongly advised to use TLS services that are provided by FIPS 140-2 validated cryptomodules.

A cryptomodule, whether it is a software library or a hardware device, basically consists of three parts:

- Components that implement cryptographic algorithms (symmetric and asymmetric algorithms, hash algorithms, random number generator algorithms, and message authentication code algorithms)
- Components that call and manage cryptographic functions (inputs and outputs include cryptographic keys and so-called critical security parameters)
- A physical container around the components that implement cryptographic algorithms and the components that call and manage cryptographic functions
The security of a cryptomodule and its services (and the web applications that call the cryptomodule) depend on the correct implementation and integration of each of these three parts. In addition, the cryptomodule must be used and accessed securely. The includes consideration for:

- Calling and managing cryptographic functions
- Securely Handling inputs and output
- Ensuring the secure construction of the physical container around the components
In order to leverage the benefits of TLS it is important to use a TLS service (e.g. library, web framework, web application server) which has been FIPS 140-2 validated. In addition, the cryptomodule must be installed, configured and operated in either an approved or an allowed mode to provide a high degree of certainty that the FIPS 140-2 validated cryptomodule is providing the expected security services in the expected manner.

If the system is legally required to use FIPS 140-2 encryption (e.g., owned or operated by or on behalf of the U.S. Government) then TLS must be used and SSL disabled. Details on why SSL is unacceptable are described in Section 7.1 of Implementation Guidance for FIPS PUB 140-2 and the Cryptographic Module Validation Program.

Further reading on the use of TLS to protect highly sensitive data against determined attackers can be viewed in SP800-52 Guidelines for the Selection and Use of Transport Layer Security (TLS) Implementations

## Secure Server Design

### Rule - Use TLS for All Login Pages and All Authenticated Pages
The login page and all subsequent authenticated pages must be exclusively accessed over TLS. The initial login page, referred to as the "login landing page", must be served over TLS. Failure to utilize TLS for the login landing page allows an attacker to modify the login form action, causing the user's credentials to be posted to an arbitrary location. Failure to utilize TLS for authenticated pages after the login enables an attacker to view the unencrypted session ID and compromise the user's authenticated session.

### Rule - Use TLS on Any Networks (External and Internal) Transmitting Sensitive Data
All networks, both external and internal, which transmit sensitive data must utilize TLS or an equivalent transport layer security mechanism. It is not sufficient to claim that access to the internal network is "restricted to employees". Numerous recent data compromises have shown that the internal network can be breached by attackers. In these attacks, sniffers have been installed to access unencrypted sensitive data sent on the internal network.

### Rule - Do Not Provide Non-TLS Pages for Secure Content
All pages which are available over TLS must not be available over a non-TLS connection. A user may inadvertently bookmark or manually type a URL to a HTTP page (e.g. http://example.com/myaccount) within the authenticated portion of the application. If this request is processed by the application then the response, and any sensitive data, would be returned to the user over the clear text HTTP.

### Rule - REMOVED - Do Not Perform Redirects from Non-TLS Page to TLS Login Page
This recommendation has been removed. Ultimately, the below guidance will only provide user education and cannot provide any technical controls to protect the user against a man-in-the-middle attack.

--

A common practice is to redirect users that have requested a non-TLS version of the login page to the TLS version (e.g. http://example.com/login redirects to https://example.com/login). This practice creates an additional attack vector for a man in the middle attack. In addition, redirecting from non-TLS versions to the TLS version reinforces to the user that the practice of requesting the non-TLS page is acceptable and secure.

In this scenario, the man-in-the-middle attack is used by the attacker to intercept the non-TLS to TLS redirect message. The attacker then injects the HTML of the actual login page and changes the form to post over unencrypted HTTP. This allows the attacker to view the user's credentials as they are transmitted in the clear.

It is recommended to display a security warning message to the user whenever the non-TLS login page is requested. This security warning should urge the user to always type "HTTPS" into the browser or bookmark the secure login page. This approach will help educate users on the correct and most secure method of accessing the application.

Currently there are no controls that an application can enforce to entirely mitigate this risk. Ultimately, this issue is the responsibility of the user since the application cannot prevent the user from initially typing http://example.com/login (versus HTTPS).

Note: Strict Transport Security will address this issue and will provide a server side control to instruct supporting browsers that the site should only be accessed over HTTPS

### Rule - Do Not Mix TLS and Non-TLS Content
A page that is available over TLS must be comprised completely of content which is transmitted over TLS. The page must not contain any content that is transmitted over unencrypted HTTP. This includes content from unrelated third party sites.

An attacker could intercept any of the data transmitted over the unencrypted HTTP and inject malicious content into the user's page. This malicious content would be included in the page even if the overall page is served over TLS. In addition, an attacker could steal the user's session cookie that is transmitted with any non-TLS requests. This is possible if the cookie's 'secure' flag is not set. See the rule 'Use "Secure" Cookie Flag'

### Rule - Use "Secure" Cookie Flag
The "Secure" flag must be set for all user cookies. Failure to use the "secure" flag enables an attacker to access the session cookie by tricking the user's browser into submitting a request to an unencrypted page on the site. This attack is possible even if the server is not configured to offer HTTP content since the attacker is monitoring the requests and does not care if the server responds with a 404 or doesn't respond at all.

### Rule - Keep Sensitive Data Out of the URL
Sensitive data must not be transmitted via URL arguments. A more appropriate place is to store sensitive data in a server side repository or within the user's session. When using TLS the URL arguments and values are encrypted during transit. However, there are two methods that the URL arguments and values could be exposed.

1. The entire URL is cached within the local user's browser history. This may expose sensitive data to any other user of the workstation.

2. The entire URL is exposed if the user clicks on a link to another HTTPS site. This may expose sensitive data within the referral field to the third party site. This exposure occurs in most browsers and will only occur on transitions between two TLS sites.

For example, a user following a link on https://example.com which leads to https://someOtherexample.com would expose the full URL of https://example.com (including URL arguments) in the referral header (within most browsers). This would not be the case if the user followed a link on https://example.com to http://someHTTPexample.com

### Rule - Prevent Caching of Sensitive Data
The TLS protocol provides confidentiality only for data in transit but it does not help with potential data leakage issues at the client or intermediary proxies. As a result, it is frequently prudent to instruct these nodes not to cache or persist sensitive data. One option is to add anticaching headers to relevant HTTP responses, (for example, "Cache-Control: no-cache, no-store" and "Expires: 0" for coverage of many modern browsers as of 2013). For compatibility with HTTP/1.0 (i.e., when user agents are really old or the webserver works around quirks by forcing HTTP/1.0) the response should also include the header "Pragma: no-cache". More information is available in HTTP 1.1 RFC 2616, section 14.9.

### Rule - Use HTTP Strict Transport Security
A new browser security setting called HTTP Strict Transport Security (HSTS) will significantly enhance the implementation of TLS for a domain. HSTS is enabled via a special response header and this instructs compatible browsers to enforce the following security controls:

All requests to the domain will be sent over HTTPS
Any attempts to send an HTTP requests to the domain will be automatically upgraded by the browser to HTTPS before the request is sent
If a user encounters a bad SSL certificate, the user will receive an error message and will not be allowed to override the warning message
Additional information on HSTS can be found at https://www.owasp.org/index.php/HTTP_Strict_Transport_Security and also on the OWASP AppSecTutorial Series - Episode 4

### Rule - Prefer Ephemeral Key Exchanges
Ephemeral key exchanges are based on Diffie-Hellman and use per-session, temporary keys during the initial SSL/TLS handshake. They provide perfect forward secrecy (PFS), which means a compromise of the server's long term signing key does not compromise the confidentiality of past session. When the server uses an ephemeral key, the server will sign the temporary key with its long term key (the long term key is the customary key available in its certificate).

Use cryptographic parameters (like DH-parameter) that use a secure length that match to the supported keylength of your certificate (>=2048 bits or equivalent Elliptic Curves). As some middleware had some issues with this, upgrade to the latest version.

If you have a server farm and are providing forward secrecy, then you might have to disable session resumption. For example, Apache writes the session id's and master secrets to disk so all servers in the farm can participate in resuming a session (there is currently no in-memory mechanism to achieve the sharing). Writing the session id and master secret to disk undermines forward secrecy.

## Server Certificate and Protocol Configuration

Note: If using a FIPS 140-2 cryptomodule disregard the following rules and defer to the recommended configuration for the particular cryptomodule.

### Rule - Be aware of and have a plan for the SHA-1 deprecation plan
In order to avoid presenting end users with progressive certificate warnings, organizations must proactively address the browser vendor's upcoming SHA-1 deprecation plans. The Google Chrome plan is probably the most specific and aggressive at this point: Gradually sunsetting SHA-1

If your organization has no SHA256 compatibility issues then it may be appropriate to move your site to a SHA256 signed certificate/chain. If there are, or may be, issues - you should ensure that your SHA-1 certificates expire before 1/1/2017.

### Rule - Use an Appropriate Certification Authority for the Application's User Base
An application user must never be presented with a warning that the certificate was signed by an unknown or untrusted authority. The application's user population must have access to the public certificate of the certification authority which issued the server's certificate. For Internet accessible websites, the most effective method of achieving this goal is to purchase the TLS certificate from a recognize certification authority. Popular Internet browsers already contain the public certificates of these recognized certification authorities.

Internal applications with a limited user population can use an internal certification authority provided its public certificate is securely distributed to all users. However, remember that all certificates issued by this certification authority will be trusted by the users. Therefore, utilize controls to protect the private key and ensure that only authorized individuals have the ability to sign certificates.

The use of self signed certificates is never acceptable. Self signed certificates negate the benefit of end-point authentication and also significantly decrease the ability for an individual to detect a man-in-the-middle attack.

### Rule - Only Support Strong Protocols
SSL/TLS is a collection of protocols. Weaknesses have been identified with earlier SSL protocols, including SSLv2 and SSLv3. The best practice for transport layer protection is to only provide support for the TLS protocols - TLS1.0, TLS 1.1 and TLS 1.2. This configuration will provide maximum protection against skilled and determined attackers and is appropriate for applications handling sensitive data or performing critical operations.

Nearly all modern browsers support at least TLS 1.0. As of February 2013, contemporary browsers (Chrome v20+, IE v8+, Opera v10+, and Safari v5+) support TLS 1.1 and TLS 1.2. You should provide support for TLS 1.1 and TLS 1.2 to accommodate clients which support the protocols. The client and server (usually) negotiate the best protocol, that is supported on both sides.

TLS 1.0 is still widely used as 'best' protocol by a lot of browsers, that are not patched to the very latest version. It suffers CBC Chaining attacks and Padding Oracle attacks. TLSv1.0 should only be used only after risk analysis and acceptance.

### Under no circumstances neither SSLv2 nor SSLv3 should be enabled as a protocol selection:

The SSLv2 protocol is broken and does not provide adequate transport layer protection.
SSLv3 had been known for weaknesses which severely compromise the channel's security long before the 'POODLE'-Bug finally stopped to tolerate this protocol by October 2014. Switching off SSLv3 terminates the support of legacy browsers like IE6/XP and elder.
Rule - Only Support Strong Cryptographic Ciphers
Each protocol (SSLv3, TLSv1.0, etc) provides cipher suites. As of TLS 1.2, there is support for over 300 suites (320+ and counting), including national vanity cipher suites. The strength of the encryption used within a TLS session is determined by the encryption cipher negotiated between the server and the browser. In order to ensure that only strong cryptographic ciphers are selected the server must be modified to disable the use of weak ciphers and to configure the ciphers in an adequate order. It is recommended to configure the server to only support strong ciphers and to use sufficiently large key sizes. In general, the following should be observed when selecting CipherSuites:

### Use the very latest recommendations, they may be volantile these days
- Setup your Policy to get a Whitelist for recommended Ciphers, e.g.:
- Activate to set the Cipher Order by the Server
- Highest Priority for Ciphers that support 'Forward Secrecy' (-> Support ephemeral Diffie-Hellman key exchange) [1]
- Favor DHE over ECDHE (and monitor the CPU usage, see Notes below), ECDHE lacks now of really reliable Elliptic Curves, see discussion about secp{224,256,384,521}r1 and secp256k1, cf. [2], [3]. The solution might be to use Brainpool Curves [German], defined for TLS in RFC 7027, or Edwards Curves. The most promising candidate for the latter is 'Curve25519', that is not yet defined for TLS, cf. IANA
- Use RSA-Keys (no DSA/DSS: they get very weak, if a bad entropy source is used during signing, cf. [4], [5])
- Favor GCM over CBC regardless of the cipher size
- Watch also for Stream Ciphers which XOR the key stream with plaintext (such as AES/CTR mode)
- Priorize the ciphers by the sizes of the Cipher and the MAC
- Use SHA1 or above for digests, prefer SHA2 (or equivalent)
- Disable weak ciphers (which is implicitly done by this whitelist) without disabling legacy browsers and bots that have to be supported (find the best compromise), actually the cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA (0xa) does this job.
- Disable cipher suites that do not offer encryption (eNULL, NULL)
- Disable cipher suites that do not offer authentication (aNULL). aNULL includes anonymous cipher suites ADH (Anonymous Diffie-Hellman) and AECDH (Anonymous Elliptic Curve Diffie Hellman).
- Disable export level ciphers (EXP, eg. ciphers containing DES)
- Disable key sizes smaller than 128 bits for encrypting payload traffic (see BSI: TR-02102 Part 2 (German))
- Disable the use of MD5 as a hashing mechanism for payload traffic
- Disable the use of IDEA Cipher Suites (see [6])
- Disable RC4 cipher suites (see [7])
- Ciphers should be usable for DH-Pamameters >= 2048 bits, without blocking legacy browsers (The cipher ‘DHE-RSA-AES128-SHA’ is suppressed as some browsers like to use it but are not capable to cope with DH-Params > 1024 bits.)
Define a Cipher String that works with different Versions of your encryption tool, like openssl
- Verify your cipher string
with an audit-tool, like OWASP 'O-Saft' (OWASP SSL audit for testers / OWASP SSL advanced forensic tool)
listing it manually with your encryption software, e.g. openssl ciphers -v <cipher-string> (the result may differ by version), e.g.:
openssl ciphers -v "EDH+aRSA+AESGCM:EDH+aRSA+AES:DHE-RSA-AES256-SHA:EECDH+aRSA+AESGCM:EECDH+aRSA+AES:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:RSA+AESGCM:RSA+AES+SHA:DES-CBC3-SHA:-DHE-RSA-AES128-SHA" 
#add optionally ':!aNULL:!eNULL:!LOW:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:!ADH:!IDEA' to protect older Versions of OpenSSL
#you may use openssl ciphers -V "..." for openssl >= 1.0.1:
```
0x00,0x9F - DHE-RSA-AES256-GCM-SHA384   TLSv1.2 Kx=DH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
0x00,0x9E - DHE-RSA-AES128-GCM-SHA256   TLSv1.2 Kx=DH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
0x00,0x6B - DHE-RSA-AES256-SHA256       TLSv1.2 Kx=DH     Au=RSA  Enc=AES(256)    Mac=SHA256
0x00,0x39 - DHE-RSA-AES256-SHA          SSLv3   Kx=DH     Au=RSA  Enc=AES(256)    Mac=SHA1
0x00,0x67 - DHE-RSA-AES128-SHA256       TLSv1.2 Kx=DH     Au=RSA  Enc=AES(128)    Mac=SHA2560xC0,
0x30 - ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH   Au=RSA  Enc=AESGCM(256) Mac=AEAD
0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH   Au=RSA  Enc=AESGCM(128) Mac=AEAD
0xC0,0x28 - ECDHE-RSA-AES256-SHA384     TLSv1.2 Kx=ECDH   Au=RSA  Enc=AES(256)    Mac=SHA384
0xC0,0x14 - ECDHE-RSA-AES256-SHA        SSLv3   Kx=ECDH   Au=RSA  Enc=AES(256)    Mac=SHA1
0xC0,0x27 - ECDHE-RSA-AES128-SHA256     TLSv1.2 Kx=ECDH   Au=RSA  Enc=AES(128)    Mac=SHA256
0xC0,0x13 - ECDHE-RSA-AES128-SHA        SSLv3   Kx=ECDH   Au=RSA  Enc=AES(128)    Mac=SHA1
0x00,0x9D - AES256-GCM-SHA384           TLSv1.2 Kx=RSA    Au=RSA  Enc=AESGCM(256) Mac=AEAD
0x00,0x9C - AES128-GCM-SHA256           TLSv1.2 Kx=RSA    Au=RSA  Enc=AESGCM(128) Mac=AEAD
0x00,0x35 - AES256-SHA                  SSLv3   Kx=RSA    Au=RSA  Enc=AES(256)    Mac=SHA1
0x00,0x2F - AES128-SHA                  SSLv3   Kx=RSA    Au=RSA  Enc=AES(128)    Mac=SHA1
0x00,0x0A - DES-CBC3-SHA                SSLv3   Kx=RSA    Au=RSA  Enc=3DES(168)   Mac=SHA1
```
Inform yourself how to securely configure the settings for your used services or hardware, e.g. BetterCrypto.org: Applied Crypto Hardening (DRAFT)
Check new software and hardware versions for new security settings.
Notes:

According to my researches the most common browsers should be supported with this setting, too (see also SSL Labs: SSL Server Test -> SSL Report -> Handshake Simulation).
Monitor the performance of your server, e.g. the TLS handshake with DHE hinders the CPU abt 2.4 times more than ECDHE, cf. Vincent Bernat, 2011, nmav's Blog, 2011.
Use of Ephemeral Diffie-Hellman key exchange will protect confidentiality of the transmitted plaintext data even if the corresponding RSA or DSS server private key got compromised. An attacker would have to perform active man-in-the-middle attack at the time of the key exchange to be able to extract the transmitted plaintext. All modern browsers support this key exchange with the notable exception of Internet Explorer prior to Windows Vista.
Additional information can be obtained within the TLS 1.2 RFC 5246, SSL Labs: 'SSL/TLS Deployment Best Practices', BSI: 'TR-02102 Part 2 (German)', ENISA: 'Algorithms, Key Sizes and Parameters Report' and FIPS 140-2 IG.

### Rule - Support TLS-PSK and TLS-SRP for Mutual Authentication
When using a shared secret or password offer TLS-PSK (Pre-Shared Key) or TLS-SRP (Secure Remote Password), which are known as Password Authenticated Key Exchange (PAKEs). TLS-PSK and TLS-SRP properly bind the channel, which refers to the cryptographic binding between the outer tunnel and the inner authentication protocol. IANA currently reserves 79 PSK cipehr suites and 9 SRP cipher suites.

Basic authentication places the user's password on the wire in the plain text after a server authenticates itself. Basic authentication only provides unilateral authentication. In contrast, both TLS-PSK and TLS-SRP provide mutual authentication, meaning each party proves it knows the password without placing the password on the wire in the plain text.

Finally, using a PAKE removes the need to trust an outside party, such as a Certification Authority (CA).

### Rule - Only Support Secure Renegotiations
A design weakness in TLS, identified as CVE-2009-3555, allows an attacker to inject a plaintext of his choice into a TLS session of a victim. In the HTTPS context the attacker might be able to inject his own HTTP requests on behalf of the victim. The issue can be mitigated either by disabling support for TLS renegotiations or by supporting only renegotiations compliant with RFC 5746. All modern browsers have been updated to comply with this RFC.

### Rule - Disable Compression
Compression Ratio Info-leak Made Easy (CRIME) is an exploit against the data compression scheme used by the TLS and SPDY protocols. The exploit allows an adversary to recover user authentication cookies from HTTPS. The recovered cookie can be subsequently used for session hijacking attacks.

### Rule - Use Strong Keys & Protect Them
The private key used to generate the cipher key must be sufficiently strong for the anticipated lifetime of the private key and corresponding certificate. The current best practice is to select a key size of at least 2048 bits. Additional information on key lifetimes and comparable key strengths can be found in [8], NIST SP 800-57. In addition, the private key must be stored in a location that is protected from unauthorized access.

### Rule - Use a Certificate That Supports Required Domain Names
A user should never be presented with a certificate error, including prompts to reconcile domain or hostname mismatches, or expired certificates. If the application is available at both https://www.example.com and https://example.com then an appropriate certificate, or certificates, must be presented to accommodate the situation. The presence of certificate errors desensitizes users to TLS error messages and increases the possibility an attacker could launch a convincing phishing or man-in-the-middle attack.

For example, consider a web application accessible at https://abc.example.com and https://xyz.example.com. One certificate should be acquired for the host or server abc.example.com; and a second certificate for host or server xyz.example.com. In both cases, the hostname would be present in the Subject's Common Name (CN).

Alternatively, the Subject Alternate Names (SANs) can be used to provide a specific listing of multiple names where the certificate is valid. In the example above, the certificate could list the Subject's CN as example.com, and list two SANs: abc.example.com and xyz.example.com. These certificates are sometimes referred to as "multiple domain certificates".

### Rule - Use Fully Qualified Names in Certificates
Use fully qualified names in the DNS name field, and do not use unqualifed names (e.g., 'www'), local names (e.g., 'localhost'), or private IP addresses (e.g., 192.168.1.1) in the DNS name field. Unqualifed names, local names, or private IP addresses violate the certificate specification.

### Rule - Do Not Use Wildcard Certificates
You should refrain from using wildcard certificates. Though they are expedient at circumventing annoying user prompts, they also violate the principal of least privilege and asks the user to trust all machines, including developer's machines, the secretary's machine in the lobby and the sign-in kiosk. Obtaining access to the private key is left as an exercise for the attacker, but its made much easier when stored on the file system unprotected.

Statistics gathered by Qualys for Internet SSL Survey 2010 indicate wildcard certificates have a 4.4% share, so the practice is not standard for public facing hosts. Finally, wildcard certificates violate EV Certificate Guidelines.

### Rule - Do Not Use RFC 1918 Addresses in Certificates
Certificates should not use private addresses. RFC 1918 is Address Allocation for Private Internets. Private addresses are Internet Assigned Numbers Authority (IANA) reserved and include 192.168/16, 172.16/12, and 10/8.

Certificates issued with private addresses violate EV Certificate Guidelines. In addition, Peter Gutmann writes in in Engineering Security: "This one is particularly troublesome because, in combination with the router-compromise attacks... and ...OSCP-defeating measures, it allows an attacker to spoof any EV-certificate site."

### Rule - Always Provide All Needed Certificates
Clients attempt to solve the problem of identifying a server or host using PKI and X509 certificate. When a user receives a server or host's certificate, the certificate must be validated back to a trusted root certification authority. This is known as path validation.

There can be one or more intermediate certificates in between the end-entity (server or host) certificate and root certificate. In addition to validating both endpoints, the user will also have to validate all intermediate certificates. Validating all intermediate certificates can be tricky because the user may not have them locally. This is a well-known PKI issue called the “Which Directory?" problem.

To avoid the “Which Directory?" problem, a server should provide the user with all required certificates used in a path validation.

# Require Re-authentication for Sensitive Features
In order to mitigate CSRF and session hijacking, it's important to require the current credentials for an account before updating sensitive account information such as the user's password, user's email, or before sensitive transactions, such as shipping a purchase to a new address. Without this countermeasure, an attacker may be able to execute sensitive transactions through a CSRF or XSS attack without needing to know the user's current credentials. Additionally, an attacker may get temporary physical access to a user's browser or steal their session ID to take over the user's session.

# Utilize Multi-Factor Authentication
Multi-factor authentication (MFA) is using more than one authentication factor to logon or process a transaction:

Something you know (account details or passwords)
Something you have (tokens or mobile phones)
Something you are (biometrics)
Authentication schemes such as One Time Passwords (OTP) implemented using a hardware token can also be key in fighting attacks such as CSRF and client-side malware. A number of hardware tokens suitable for MFA are available in the market that allow good integration with web applications. See: [2].

## SSL Client Authentication
SSL Client Authentication, also known as two-way SSL authentication, consists of both, browser and server, sending their respective SSL certificates during the TLS handshake process. Just as you can validate the authenticity of a server by using the certificate and asking a well known Certificate Authority (CA) if the certificate is valid, the server can authenticate the user by receiving a certificate from the client and validating against a third party CA or its own CA. To do this, the server must provide the user with a certificate generated specifically for him, assigning values to the subject so that these can be used to determine what user the certificate should validate. The user installs the certificate on a browser and now uses it for the website.

It is a good idea to do this when:

It is acceptable (or even preferred) that the user only has access to the website from only a single computer/browser.
The user is not easily scared by the process of installing SSL certificates on his browser or there will be someone, probably from IT support, that will do this for the user.
The website requires an extra step of security.
It is also a good thing to use when the website is for an intranet of a company or organization.
It is generally not a good idea to use this method for widely and publicly available websites that will have an average user. For example, it wouldn't be a good idea to implement this for a website like Facebook. While this technique can prevent the user from having to type a password (thus protecting against an average keylogger from stealing it), it is still considered a good idea to consider using both a password and SSL client authentication combined.

# Authentication and Error Messages
Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner.

## Authentication Responses
An application should respond with a generic error message regardless of whether the user ID or password was incorrect. It should also give no indication to the status of an existing account.

## Incorrect Response Examples
"Login for User foo: invalid password"
"Login failed, invalid user ID"
"Login failed; account disabled"
"Login failed; this user is not active"
Correct Response Example
"Login failed; Invalid userID or password"
The correct response does not indicate if the user ID or password is the incorrect parameter and hence inferring a valid user ID.

## Error Codes and URLs
The application may return a different HTTP Error code depending on the authentication attempt response. It may respond with a 200 for a positive result and a 403 for a negative result. Even though a generic error page is shown to a user, the HTTP response code may differ which can leak information about whether the account is valid or not.

# Prevent Brute-Force Attacks
If an attacker is able to guess passwords without the account becoming disabled due to failed authentication attempts, the attacker has an opportunity to continue with a brute force attack until the account is compromised. Automating brute-force/password guessing attacks on web applications is a trivial challenge. Password lockout mechanisms should be employed that lock out an account if more than a preset number of unsuccessful login attempts are made. Password lockout mechanisms have a logical weakness. An attacker that undertakes a large number of authentication attempts on known account names can produce a result that locks out entire blocks of user accounts. Given that the intent of a password lockout system is to protect from brute-force attacks, a sensible strategy is to lockout accounts for a period of time (e.g., 20 minutes). This significantly slows down attackers, while allowing the accounts to reopen automatically for legitimate users.

Also, multi-factor authentication is a very powerful deterrent when trying to prevent brute force attacks since the credentials are a moving target. When multi-factor is implemented and active, account lockout may no longer be necessary.

# Use of authentication protocols that require no password

While authentication through a user/password combination and using multi-factor authentication is considered generally secure, there are use cases where it isn't considered the best option or even safe. An example of this are third party applications that desire connecting to the web application, either from a mobile device, another website, desktop or other situations. When this happens, it is NOT considered safe to allow the third party application to store the user/password combo, since then it extends the attack surface into their hands, where it isn't in your control. For this, and other use cases, there are several authentication protocols that can protect you from exposing your users' data to attackers.

# OAuth
Open Authorization (OAuth) is a protocol that allows an application to authenticate against a server as a user, without requiring passwords or any third party server that acts as an identity provider. It uses a token generated by the server, and provides how the authorization flows most occur, so that a client, such as a mobile application, can tell the server what user is using the service.

The recommendation is to use and implement OAuth 1.0a or OAuth 2.0, since the very first version (OAuth1.0) has been found to be vulnerable to session fixation.

OAuth 2.0 relies on HTTPS for security and is currently used and implemented by API's from companies such as Facebook, Google, Twitter and Microsoft. OAuth1.0a is more difficult to use because it requires the use of cryptographic libraries for digital signatures, however does not rely on HTTPS for security and can therefore be more suited for higher risk transactions.

# OpenId
OpenId is an HTTP-based protocol that uses identity providers to validate that a user is who he says he is. It is a very simple protocol which allows a service provider initiated way for single sign-on (SSO). This allows the user to re-use a single identity given to a trusted OpenId identity provider and be the same user in multiple websites, without the need to provide any website the password, except for the OpenId identity provider.

Due to its simplicity and that it provides protection of passwords, OpenId has been well adopted. Some of the well known identity providers for OpenId are Stack Exchange, Google, Facebook and Yahoo!

For non-enterprise environment, OpenId is considered a secure and often better choice, as long as the identity provider is of trust.

# Session Management

## Web Authentication, Session Management, and Access Control

A web session is a sequence of network HTTP request and response transactions associated to the same user. Modern and complex web applications require the retaining of information or status about each user for the duration of multiple requests. Therefore, sessions provide the ability to establish variables – such as access rights and localization settings – which will apply to each and every interaction a user has with the web application for the duration of the session.

Web applications can create sessions to keep track of anonymous users after the very first user request. An example would be maintaining the user language preference. Additionally, web applications will make use of sessions once the user has authenticated. This ensures the ability to identify the user on any subsequent requests as well as being able to apply security access controls, authorized access to the user private data, and to increase the usability of the application. Therefore, current web applications can provide session capabilities both pre and post authentication.

Once an authenticated session has been established, the session ID (or token) is temporarily equivalent to the strongest authentication method used by the application, such as username and password, passphrases, one-time passwords (OTP), client-based digital certificates, smartcards, or biometrics (such as fingerprint or eye retina). See the OWASP Authentication Cheat Sheet: https://www.owasp.org/index.php/Authentication_Cheat_Sheet.

HTTP is a stateless protocol (RFC2616 [5]), where each request and response pair is independent of other web interactions. Therefore, in order to introduce the concept of a session, it is required to implement session management capabilities that link both the authentication and access control (or authorization) modules commonly available in web applications:

![](https://www.owasp.org/images/1/1d/Session-Management-Diagram_Cheat-Sheet.png)

The session ID or token binds the user authentication credentials (in the form of a user session) to the user HTTP traffic and the appropriate access controls enforced by the web application. The complexity of these three components (authentication, session management, and access control) in modern web applications, plus the fact that its implementation and binding resides on the web developer’s hands (as web development framework do not provide strict relationships between these modules), makes the implementation of a secure session management module very challenging.
The disclosure, capture, prediction, brute force, or fixation of the session ID will lead to session hijacking (or sidejacking) attacks, where an attacker is able to fully impersonate a victim user in the web application. Attackers can perform two types of session hijacking attacks, targeted or generic. In a targeted attack, the attacker’s goal is to impersonate a specific (or privileged) web application victim user. For generic attacks, the attacker’s goal is to impersonate (or get access as) any valid or legitimate user in the web application.

## Session ID Properties
In order to keep the authenticated state and track the users progress within the web application, applications provide users with a session identifier (session ID or token) that is assigned at session creation time, and is shared and exchanged by the user and the web application for the duration of the session (it is sent on every HTTP request). The session ID is a “name=value” pair.

With the goal of implementing secure session IDs, the generation of identifiers (IDs or tokens) must meet the following properties:

## Session ID Name Fingerprinting
The name used by the session ID should not be extremely descriptive nor offer unnecessary details about the purpose and meaning of the ID.

The session ID names used by the most common web application development frameworks can be easily fingerprinted [0], such as PHPSESSID (PHP), JSESSIONID (J2EE), CFID & CFTOKEN (ColdFusion), ASP.NET_SessionId (ASP .NET), etc. Therefore, the session ID name can disclose the technologies and programming languages used by the web application.

It is recommended to change the default session ID name of the web development framework to a generic name, such as “id”.

## Session ID Length
The session ID must be long enough to prevent brute force attacks, where an attacker can go through the whole range of ID values and verify the existence of valid sessions.

The session ID length must be at least 128 bits (16 bytes).

## Session ID Entropy
The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker is able to guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good PRNG (Pseudo Random Number Generator) must be used.

The session ID value must provide at least 64 bits of entropy (if a good PRNG is used, this value is estimated to be half the length of the session ID).
NOTE: The session ID entropy is really affected by other external and difficult to measure factors, such as the number of concurrent active sessions the web application commonly has, the absolute session expiration timeout, the amount of session ID guesses per second the attacker can make and the target web application can support, etc [2]. If a session ID with an entropy of 64 bits is used, it will take an attacker at least 292 years to successfully guess a valid session ID, assuming the attacker can try 10,000 guesses per second with 100,000 valid simultaneous sessions available in the web application [2].

## Session ID Content (or Value)
The session ID content (or value) must be meaningless to prevent information disclosure attacks, where an attacker is able to decode the contents of the ID and extract details of the user, the session, or the inner workings of the web application.

The session ID must simply be an identifier on the client side, and its value must never include sensitive information (or PII). The meaning and business or application logic associated to the session ID must be stored on the server side, and specifically, in session objects or in a session management database or repository. The stored information can include the client IP address, User-Agent, e-mail, username, user ID, role, privilege level, access rights, language preferences, account ID, current state, last login, session timeouts, and other internal session details. If the session objects and properties contain sensitive information, such as credit card numbers, it is required to duly encrypt and protect the session management repository.

It is recommended to create cryptographically strong session IDs through the usage of cryptographic hash functions such as SHA1 (160 bits).

## Session Management Implementation
The session management implementation defines the exchange mechanism that will be used between the user and the web application to share and continuously exchange the session ID. There are multiple mechanisms available in HTTP to maintain session state within web applications, such as cookies (standard HTTP header), URL parameters (URL rewriting – RFC 2396), URL arguments on GET requests, body arguments on POST requests, such as hidden form fields (HTML forms), or proprietary HTTP headers.

The preferred session ID exchange mechanism should allow defining advanced token properties, such as the token expiration date and time, or granular usage constraints. This is one of the reasons why cookies (RFCs 2109 & 2965 & 6265 [1]) are one of the most extensively used session ID exchange mechanisms, offering advanced capabilities not available in other methods.

The usage of specific session ID exchange mechanisms, such as those where the ID is included in the URL, might disclose the session ID (in web links and logs, web browser history and bookmarks, the Referer header or search engines), as well as facilitate other attacks, such as the manipulation of the ID or session fixation attacks [3].

## Built-in Session Management Implementations
Web development frameworks, such as J2EE, ASP .NET, PHP, and others, provide their own session management features and associated implementation. It is recommended to use these built-in frameworks versus building a home made one from scratch, as they are used worldwide on multiple web environments and have been tested by the web application security and development communities over time.

However, be advised that these frameworks have also presented vulnerabilities and weaknesses in the past, so it is always recommended to use the latest version available, that potentially fixes all the well-known vulnerabilities, as well as review and change the default configuration to enhance its security by following the recommendations described along this document.

The storage capabilities or repository used by the session management mechanism to temporarily save the session IDs must be secure, protecting the session IDs against local or remote accidental disclosure or unauthorized access.

## Used vs. Accepted Session ID Exchange Mechanisms
A specific web application can make use of a particular session ID exchange mechanism by default, such as cookies. However, if a user submits a session ID through a different exchange mechanism, such as a URL parameter, the web application might accept it. Effectively, the web application can use both mechanisms, cookies or URL parameters, or even switch from one to the other (automatic URL rewriting) if certain conditions are met (for example, the existence of web clients without cookies support or when cookies are not accepted due to user privacy concerns).

For this reason, it is crucial to differentiate between the mechanisms used by the web application (by default) to exchange session IDs and the mechanisms accepted by the web application to process and manage session IDs. Web applications must limit the accepted session tracking mechanisms to only those selected and used by design.

## Transport Layer Security
In order to protect the session ID exchange from active eavesdropping and passive disclosure in the network traffic, it is mandatory to use an encrypted HTTPS (SSL/TLS) connection for the entire web session, not only for the authentication process where the user credentials are exchanged.

Additionally, the “Secure” cookie attribute (see below) must be used to ensure the session ID is only exchanged through an encrypted channel. The usage of an encrypted communication channel also protects the session against some session fixation attacks where the attacker is able to intercept and manipulate the web traffic to inject (or fix) the session ID on the victims web browser [4].

The following set of HTTPS (SSL/TLS) best practices are focused on protecting the session ID (specifically when cookies are used) and helping with the integration of HTTPS within the web application:

Web applications should never switch a given session from HTTP to HTTPS, or viceversa, as this will disclose the session ID in the clear through the network.
Web applications should not mix encrypted and unencrypted contents (HTML pages, images, CSS, Javascript files, etc) on the same host (or even domain - see the “domain” cookie attribute), as the request of any web object over an unencrypted channel might disclose the session ID.
Web applications, in general, should not offer public unencrypted contents and private encrypted contents from the same host. It is recommended to instead use two different hosts, such as www.example.com over HTTP (unencrypted) for the public contents, and secure.example.com over HTTPS (encrypted) for the private and sensitive contents (where sessions exist). The former host only has port TCP/80 open, while the later only has port TCP/443 open.
Web applications should avoid the extremely common HTTP to HTTPS redirection on the home page (using a 30x HTTP response), as this single unprotected HTTP request/response exchange can be used by an attacker to gather (or fix) a valid session ID.
Web applications should make use of “HTTP Strict Transport Security (HSTS)” (previously called STS) to enforce HTTPS connections.
See the OWASP Transport Layer Protection Cheat Sheet: https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet.

It is important to emphasize that SSL/TLS (HTTPS) does not protect against session ID prediction, brute force, client-side tampering or fixation. Yet, session ID disclosure and capture from the network traffic is one of the most prevalent attack vectors even today.


## Cookies
The session ID exchange mechanism based on cookies provides multiple security features in the form of cookie attributes that can be used to protect the exchange of the session ID:

### Secure Attribute
The “Secure” cookie attribute instructs web browsers to only send the cookie through an encrypted HTTPS (SSL/TLS) connection. This session protection mechanism is mandatory to prevent the disclosure of the session ID through MitM (Man-in-the-Middle) attacks. It ensures that an attacker cannot simply capture the session ID from web browser traffic.

Forcing the web application to only use HTTPS for its communication (even when port TCP/80, HTTP, is closed in the web application host) does not protect against session ID disclosure if the “Secure” cookie has not been set - the web browser can be deceived to disclose the session ID over an unencrypted HTTP connection. The attacker can intercept and manipulate the victim user traffic and inject an HTTP unencrypted reference to the web application that will force the web browser to submit the session ID in the clear.

### HttpOnly Attribute
The “HttpOnly” cookie attribute instructs web browsers not to allow scripts (e.g. JavaScript or VBscript) an ability to access the cookies via the DOM document.cookie object. This session ID protection is mandatory to prevent session ID stealing through XSS attacks.

See the OWASP XSS Prevention Cheat Sheet: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet.

### Domain and Path Attributes
The “Domain” cookie attribute instructs web browsers to only send the cookie to the specified domain and all subdomains. If the attribute is not set, by default the cookie will only be sent to the origin server. The “Path” cookie attribute instructs web browsers to only send the cookie to the specified directory or subdirectories (or paths or resources) within the web application. If the attribute is not set, by default the cookie will only be sent for the directory (or path) of the resource requested and setting the cookie.

It is recommended to use a narrow or restricted scope for these two attributes. In this way, the “Domain” attribute should not be set (restricting the cookie just to the origin server) and the “Path” attribute should be set as restrictive as possible to the web application path that makes use of the session ID.

Setting the “Domain” attribute to a too permissive value, such as “example.com” allows an attacker to launch attacks on the session IDs between different hosts and web applications belonging to the same domain, known as cross-subdomain cookies. For example, vulnerabilities in www.example.com might allow an attacker to get access to the session IDs from secure.example.com.

Additionally, it is recommended not to mix web applications of different security levels on the same domain. Vulnerabilities in one of the web applications would allow an attacker to set the session ID for a different web application on the same domain by using a permissive “Domain” attribute (such as “example.com”) which is a technique that can be used in session fixation attacks [4].

Although the “Path” attribute allows the isolation of session IDs between different web applications using different paths on the same host, it is highly recommended not to run different web applications (especially from different security levels or scopes) on the same host. Other methods can be used by these applications to access the session IDs, such as the “document.cookie” object. Also, any web application can set cookies for any path on that host.

Cookies are vulnerable to DNS spoofing/hijacking/poisoning attacks, where an attacker can manipulate the DNS resolution to force the web browser to disclose the session ID for a given host or domain.

### Expire and Max-Age Attributes
Session management mechanisms based on cookies can make use of two types of cookies, non-persistent (or session) cookies, and persistent cookies. If a cookie presents the “Max-Age” (that has preference over “Expires”) or “Expires” attributes, it will be considered a persistent cookie and will be stored on disk by the web browser based until the expiration time. Typically, session management capabilities to track users after authentication make use of non-persistent cookies. This forces the session to disappear from the client if the current web browser instance is closed. Therefore, it is highly recommended to use non-persistent cookies for session management purposes, so that the session ID does not remain on the web client cache for long periods of time, from where an attacker can obtain it.

## Session ID Life Cycle

### Session ID Generation and Verification: Permissive and Strict Session Management
There are two types of session management mechanisms for web applications, permissive and strict, related to session fixation vulnerabilities. The permissive mechanism allow the web application to initially accept any session ID value set by the user as valid, creating a new session for it, while the strict mechanism enforces that the web application will only accept session ID values that have been previously generated by the web application.

Although the most common mechanism in use today is the strict one (more secure). Developers must ensure that the web application does not use a permissive mechanism under certain circumstances. Web applications should never accept a session ID they have never generated, and in case of receiving one, they should generate and offer the user a new valid session ID. Additionally, this scenario should be detected as a suspicious activity and an alert should be generated.

### Manage Session ID as Any Other User Input
Session IDs must be considered untrusted, as any other user input processed by the web application, and they must be thoroughly validated and verified. Depending on the session management mechanism used, the session ID will be received in a GET or POST parameter, in the URL or in an HTTP header (e.g. cookies). If web applications do not validate and filter out invalid session ID values before processing them, they can potentially be used to exploit other web vulnerabilities, such as SQL injection if the session IDs are stored on a relational database, or persistent XSS if the session IDs are stored and reflected back afterwards by the web application.

### Renew the Session ID After Any Privilege Level Change
The session ID must be renewed or regenerated by the web application after any privilege level change within the associated user session. The most common scenario where the session ID regeneration is mandatory is during the authentication process, as the privilege level of the user changes from the unauthenticated (or anonymous) state to the authenticated state. Other common scenarios must also be considered, such as password changes, permission changes or switching from a regular user role to an administrator role within the web application. For all these web application critical pages, previous session IDs have to be ignored, a new session ID must be assigned to every new request received for the critical resource, and the old or previous session ID must be destroyed.

The most common web development frameworks provide session functions and methods to renew the session ID, such as “request.getSession(true) & HttpSession.invalidate()” (J2EE), “Session.Abandon() & Response.Cookies.Add(new…)“ (ASP .NET), or “session_start() & session_regenerate_id(true)” (PHP).

The session ID regeneration is mandatory to prevent session fixation attacks [3], where an attacker sets the session ID on the victims user web browser instead of gathering the victims session ID, as in most of the other session-based attacks, and independently of using HTTP or HTTPS. This protection mitigates the impact of other web-based vulnerabilities that can also be used to launch session fixation attacks, such as HTTP response splitting or XSS [4].

A complementary recommendation is to use a different session ID or token name (or set of session IDs) pre and post authentication, so that the web application can keep track of anonymous users and authenticated users without the risk of exposing or binding the user session between both states.

### Considerations When Using Multiple Cookies
If the web application uses cookies as the session ID exchange mechanism, and multiple cookies are set for a given session, the web application must verify all cookies (and enforce relationships between them) before allowing access to the user session.

It is very common for web applications to set a user cookie pre-authentication over HTTP to keep track of unauthenticated (or anonymous) users. Once the user authenticates in the web application, a new post-authentication secure cookie is set over HTTPS, and a binding between both cookies and the user session is established. If the web application does not verify both cookies for authenticated sessions, an attacker can make use of the pre-authentication unprotected cookie to get access to the authenticated user session [4].

Web applications should try to avoid the same cookie name for different paths or domain scopes within the same web application, as this increases the complexity of the solution and potentially introduces scoping issues.

### Session Expiration
In order to minimize the time period an attacker can launch attacks over active sessions and hijack them, it is mandatory to set expiration timeouts for every session, establishing the amount of time a session will remain active. Insufficient session expiration by the web application increases the exposure of other session-based attacks, as for the attacker to be able to reuse a valid session ID and hijack the associated session, it must still be active.

The shorter the session interval is, the lesser the time an attacker has to use the valid session ID. The session expiration timeout values must be set accordingly with the purpose and nature of the web application, and balance security and usability, so that the user can comfortably complete the operations within the web application without his session frequently expiring. Both the idle and absolute timeout values are highly dependent on how critical the web application and its data are. Common idle timeouts ranges are 2-5 minutes for high-value applications and 15- 30 minutes for low risk applications.

When a session expires, the web application must take active actions to invalidate the session on both sides, client and server. The latter is the most relevant and mandatory from a security perspective.

For most session exchange mechanisms, client side actions to invalidate the session ID are based on clearing out the token value. For example, to invalidate a cookie it is recommended to provide an empty (or invalid) value for the session ID, and set the “Expires” (or “Max-Age”) attribute to a date from the past (in case a persistent cookie is being used):

```
Set-Cookie: id=; Expires=Friday, 17-May-03 18:45:00 GMT 
```

In order to close and invalidate the session on the server side, it is mandatory for the web application to take active actions when the session expires, or the user actively logs out, by using the functions and methods offered by the session management mechanisms, such as “HttpSession.invalidate()” (J2EE), “Session.Abandon()“ (ASP .NET) or “session_destroy()/unset()“ (PHP).

### Automatic Session Expiration

#### Idle Timeout
All sessions should implement an idle or inactivity timeout. This timeout defines the amount of time a session will remain active in case there is no activity in the session, closing and invalidating the session upon the defined idle period since the last HTTP request received by the web application for a given session ID.

The idle timeout limits the chances an attacker has to guess and use a valid session ID from another user. However, if the attacker is able to hijack a given session, the idle timeout does not limit the attacker’s actions, as he can generate activity on the session periodically to keep the session active for longer periods of time.

Session timeout management and expiration must be enforced server-side. If the client is used to enforce the session timeout, for example using the session token or other client parameters to track time references (e.g. number of minutes since login time), an attacker could manipulate these to extend the session duration.

#### Absolute Timeout
All sessions should implement an absolute timeout, regardless of session activity. This timeout defines the maximum amount of time a session can be active, closing and invalidating the session upon the defined absolute period since the given session was initially created by the web application. After invalidating the session, the user is forced to (re)authenticate again in the web application and establish a new session.

The absolute session limits the amount of time an attacker can use a hijacked session and impersonate the victim user.

#### Renewal Timeout
Alternatively, the web application can implement an additional renewal timeout after which the session ID is automatically renewed, in the middle of the user session, and independently of the session activity and, therefore, of the idle timeout.

After a specific amount of time since the session was initially created, the web application can regenerate a new ID for the user session and try to set it, or renew it, on the client. The previous session ID value would still be valid for some time, accommodating a safety interval, before the client is aware of the new ID and starts using it. At that time, when the client switches to the new ID inside the current session, the application invalidates the previous ID.

This scenario minimizes the amount of time a given session ID value, potentially obtained by an attacker, can be reused to hijack the user session, even when the victim user session is still active. The user session remains alive and open on the legitimate client, although its associated session ID value is transparently renewed periodically during the session duration, every time the renewal timeout expires. Therefore, the renewal timeout complements the idle and absolute timeouts, specially when the absolute timeout value extends significantly over time (e.g. it is an application requirement to keep the user sessions opened for long periods of time).

Depending of the implementation, potentially there could be a race condition where the attacker with a still valid previous session ID sends a request before the victim user, right after the renewal timeout has just expired, and obtains first the value for the renewed session ID. At least in this scenario, the victim user might be aware of the attack as her session will be suddenly terminated because her associated session ID is not valid anymore.

### Manual Session Expiration
Web applications should provide mechanisms that allow security aware users to actively close their session once they have finished using the web application.

#### Logout Button
Web applications must provide a visible an easily accessible logout (logoff, exit, or close session) button that is available on the web application header or menu and reachable from every web application resource and page, so that the user can manually close the session at any time.

NOTE: Unfortunately, not all web applications facilitate users to close their current session. Thus, client-side enhancements such as the PopUp LogOut Firefox add-on [9] allow conscientious users to protect their sessions by helping to close them diligently.

### Web Content Caching
Even after the session has been closed, it might be possible to access the private or sensitive data exchanged within the session through the web browser cache. Therefore, web applications must use restrictive cache directives for all the web traffic exchanged through HTTP and HTTPS, such as the “Cache-Control: no-cache,no-store” and “Pragma: no-cache” HTTP headers [5], and/or equivalent META tags on all or (at least) sensitive web pages.

Independently of the cache policy defined by the web application, if caching web application contents is allowed, the session IDs must never be cached, so it is highly recommended to use the “Cache-Control: no-cache="Set-Cookie, Set-Cookie2"” directive, to allow web clients to cache everything except the session ID.

## Additional Client-Side Defenses for Session Management

Web applications can complement the previously described session management defenses with additional countermeasures on the client side. Client-side protections, typically in the form of JavaScript checks and verifications, are not bullet proof and can easily be defeated by a skilled attacker, but can introduce another layer of defense that has to be bypassed by intruders.

### Initial Login Timeout
Web applications can use JavaScript code in the login page to evaluate and measure the amount of time since the page was loaded and a session ID was granted. If a login attempt is tried after a specific amount of time, the client code can notify the user that the maximum amount of time to log in has passed and reload the login page, hence retrieving a new session ID.

This extra protection mechanism tries to force the renewal of the session ID pre-authentication, avoiding scenarios where a previously used (or manually set) session ID is reused by the next victim using the same computer, for example, in session fixation attacks.

### Force Session Logout On Web Browser Window Close Events
Web applications can use JavaScript code to capture all the web browser tab or window close (or even back) events and take the appropriate actions to close the current session before closing the web browser, emulating that the user has manually closed the session via the logout button.

### Disable Web Browser Cross-Tab Sessions
Web applications can use JavaScript code once the user has logged in and a session has been established to force the user to re-authenticate if a new web browser tab or window is opened against the same web application. The web application does not want to allow multiple web browser tabs or windows to share the same session. Therefore, the application tries to force the web browser to not share the same session ID simultaneously between them.

NOTE: This mechanism cannot be implemented if the session ID is exchanged through cookies, as cookies are shared by all web browser tabs/windows. 

### Automatic Client Logout
JavaScript code can be used by the web application in all (or critical) pages to automatically logout client sessions after the idle timeout expires, for example, by redirecting the user to the logout page (the same resource used by the logout button mentioned previously).

The benefit of enhancing the server-side idle timeout functionality with client-side code is that the user can see that the session has finished due to inactivity, or even can be notified in advance that the session is about to expire through a count down timer and warning messages. This user-friendly approach helps to avoid loss of work in web pages that require extensive input data due to server-side silently expired sessions.

## Session Attacks Detection

### Session ID Guessing and Brute Force Detection
If an attacker tries to guess or brute force a valid session ID, he needs to launch multiple sequential requests against the target web application using different session IDs from a single (or set of) IP address(es). Additionally, if an attacker tries to analyze the predictability of the session ID (e.g. using statistical analysis), he needs to launch multiple sequential requests from a single (or set of) IP address(es) against the target web application to gather new valid session IDs.

Web applications must be able to detect both scenarios based on the number of attempts to gather (or use) different session IDs and alert and/or block the offending IP address(es).

### Detecting Session ID Anomalies
Web applications should focus on detecting anomalies associated to the session ID, such as its manipulation. The OWASP AppSensor Project [7] provides a framework and methodology to implement built-in intrusion detection capabilities within web applications focused on the detection of anomalies and unexpected behaviors, in the form of detection points and response actions. Instead of using external protection layers, sometimes the business logic details and advanced intelligence are only available from inside the web application, where it is possible to establish multiple session related detection points, such as when an existing cookie is modified or deleted, a new cookie is added, the session ID from another user is reused, or when the user location or User-Agent changes in the middle of a session.

### Binding the Session ID to Other User Properties
With the goal of detecting (and, in some scenarios, protecting against) user misbehaviors and session hijacking, it is highly recommended to bind the session ID to other user or client properties, such as the client IP address, User-Agent, or client-based digital certificate. If the web application detects any change or anomaly between these different properties in the middle of an established session, this is a very good indicator of session manipulation and hijacking attempts, and this simple fact can be used to alert and/or terminate the suspicious session.

Although these properties cannot be used by web applications to trustingly defend against session attacks, they significantly increase the web application detection (and protection) capabilities. However, a skilled attacker can bypass these controls by reusing the same IP address assigned to the victim user by sharing the same network (very common in NAT environments, like Wi-Fi hotspots) or by using the same outbound web proxy (very common in corporate environments), or by manually modifying his User-Agent to look exactly as the victim users does.

### Logging Sessions Life Cycle: Monitoring Creation, Usage, and Destruction of Session IDs
Web applications should increase their logging capabilities by including information regarding the full life cycle of sessions. In particular, it is recommended to record session related events, such as the creation, renewal, and destruction of session IDs, as well as details about its usage within login and logout operations, privilege level changes within the session, timeout expiration, invalid session activities (when detected), and critical business operations during the session.

The log details might include a timestamp, source IP address, web target resource requested (and involved in a session operation), HTTP headers (including the User-Agent and Referer), GET and POST parameters, error codes and messages, username (or user ID), plus the session ID (cookies, URL, GET, POST…). Sensitive data like the session ID should not be included in the logs in order to protect the session logs against session ID local or remote disclosure or unauthorized access. However, some kind of session-specific information must be logged into order to correlate log entries to specific sessions. It is recommended to log a salted-hash of the session ID instead of the session ID itself in order to allow for session-specific log correlation without exposing the session ID.

In particular, web applications must thoroughly protect administrative interfaces that allow to manage all the current active sessions. Frequently these are used by support personnel to solve session related issues, or even general issues, by impersonating the user and looking at the web application as the user does.

The session logs become one of the main web application intrusion detection data sources, and can also be used by intrusion protection systems to automatically terminate sessions and/or disable user accounts when (one or many) attacks are detected. If active protections are implemented, these defensive actions must be logged too.

### Simultaneous Session Logons
It is the web application design decision to determine if multiple simultaneous logons from the same user are allowed from the same or from different client IP addresses. If the web application does not want to allow simultaneous session logons, it must take effective actions after each new authentication event, implicitly terminating the previously available session, or asking the user (through the old, new or both sessions) about the session that must remain active.

It is recommended for web applications to add user capabilities that allow checking the details of active sessions at any time, monitor and alert the user about concurrent logons, provide user features to remotely terminate sessions manually, and track account activity history (logbook) by recording multiple client details such as IP address, User-Agent, login date and time, idle time, etc.

### Session Management WAF Protections
There are situations where the web application source code is not available or cannot be modified, or when the changes required to implement the multiple security recommendations and best practices detailed above imply a full redesign of the web application architecture, and therefore, cannot be easily implemented in the short term. In these scenarios, or to complement the web application defenses, and with the goal of keeping the web application as secure as possible, it is recommended to use external protections such as Web Application Firewalls (WAFs) that can mitigate the session management threats already described.

Web Application Firewalls offer detection and protection capabilities against session based attacks. On the one hand, it is trivial for WAFs to enforce the usage of security attributes on cookies, such as the “Secure” and “HttpOnly” flags, applying basic rewriting rules on the “Set-Cookie” header for all the web application responses that set a new cookie. On the other hand, more advanced capabilities can be implemented to allow the WAF to keep track of sessions, and the corresponding session IDs, and apply all kind of protections against session fixation (by renewing the session ID on the client-side when privilege changes are detected), enforcing sticky sessions (by verifying the relationship between the session ID and other client properties, like the IP address or User-Agent), or managing session expiration (by forcing both the client and the web application to finalize the session).

The open-source ModSecurity WAF, plus the OWASP Core Rule Set [6], provide capabilities to detect and apply security cookie attributes, countermeasures against session fixation attacks, and session tracking features to enforce sticky sessions.

Taken from:

- https://www.owasp.org/index.php/Authentication_Cheat_Sheet
- https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
- https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet
- https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet
- https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
