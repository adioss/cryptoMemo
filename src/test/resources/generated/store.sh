#!/bin/sh
rm *.jks
rm *-req
rm *.cer

echo Generate root CA
keytool -keystore caroot.jks -storepass changeit -keypass changeit -alias caroot -genkeypair -keyalg RSA -dname CN=CAROOT -ext bc:c -validity 1460
keytool -keystore caroot.jks -storepass changeit -alias caroot -exportcert -file caroot.cer

echo Generate intermediate CA
keytool -keystore intermediateCA.jks -storepass changeit -keypass changeit -alias intermediateCA -genkeypair -keyalg RSA -dname CN=intermediateCA
keytool -keystore intermediateCA.jks -storepass changeit -alias caroot -importcert -trustcacerts -file caroot.cer -noprompt
echo Generate cert request intermediate CA
keytool -keystore intermediateCA.jks -storepass changeit -alias intermediateCA -certreq -file intermediateCA-req -noprompt
echo Sign cert request intermediate CA
keytool -keystore caroot.jks -storepass changeit -alias caroot -gencert -infile intermediateCA-req -outfile intermediateCA.cer -validity 3650 -ext bc=0 -rfc
echo Import signed cert request intermediate CA
keytool -keystore intermediateCA.jks -storepass changeit -alias intermediateCA -importcert -file intermediateCA.cer -noprompt

echo Generate sub intermediate CA
keytool -keystore subIntermediateCA.jks -storepass changeit -keypass changeit -alias subIntermediateCA -genkeypair -keyalg RSA -dname CN=subIntermediateCA
echo Generate cert request sub intermediate CA
keytool -keystore subIntermediateCA.jks -storepass changeit -alias subIntermediateCA -certreq -file subIntermediateCA-req -noprompt
echo Sign cert request sub intermediate CA
keytool -keystore intermediateCA.jks -storepass changeit -alias intermediateCA -gencert -infile subIntermediateCA-req -outfile subIntermediateCA.cer -validity 3650 -ext bc=0 -rfc
echo Import signed cert request sub intermediate CA
keytool -keystore subIntermediateCA.jks -storepass changeit -alias subIntermediateCA -importcert -file subIntermediateCA.cer -noprompt

echo Generate end keypair
keytool -keystore signedBySubIntermediate.jks -storepass changeit -keypass changeit -alias MY-ALIAS -genkeypair -keysize 2048 -keyalg RSA -dname CN=MY-ALIAS.my.com -noprompt
echo Generate cert request end keypair
keytool -keystore signedBySubIntermediate.jks -storepass changeit -alias MY-ALIAS -certreq -file cert-req -noprompt
echo Sign cert request end keypair with intermediate CA
keytool -keystore subIntermediateCA.jks -storepass changeit -alias subIntermediateCA -gencert -infile cert-req -outfile signedBySubIntermediate.cer -validity 3650 -rfc
echo Import signed trusted cert
keytool -keystore signedBySubIntermediate.jks -storepass changeit -alias subIntermediateCA -importcert -file subIntermediateCA.cer -noprompt
keytool -keystore signedBySubIntermediate.jks -storepass changeit -alias intermediateCA -importcert -file intermediateCA.cer -noprompt
keytool -keystore signedBySubIntermediate.jks -storepass changeit -alias caroot -importcert -file caroot.cer -noprompt
echo Import signed cert request end keypair
keytool -keystore signedBySubIntermediate.jks -storepass changeit -alias MY-ALIAS -importcert -file signedBySubIntermediate.cer -noprompt

echo Generate truststore
keytool -keystore truststore.jks -storepass changeit -alias intermediateCA -importcert -file intermediateCA.cer -noprompt

echo Clean
rm *-req
