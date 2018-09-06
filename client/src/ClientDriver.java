import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class ClientDriver {

  public static void main(String[] args) throws Exception {
    Client client = new Client();

    // get client's certificate
    FileInputStream fis = new FileInputStream("sslCertSigned.cert");
    BufferedInputStream bis = new BufferedInputStream(fis);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Certificate cert = cf.generateCertificate(bis);
    PublicKey pub = cert.getPublicKey();
    cert.verify(pub);

    // verify client's public key
    File f = new File("pub.der");
    FileInputStream fis2 = new FileInputStream(f);
    DataInputStream dis = new DataInputStream(fis2);
    byte[] pubBlob = new byte[(int) f.length()];
    dis.readFully(pubBlob);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey pub2 = keyFactory.generatePublic(new X509EncodedKeySpec(pubBlob));
    if (pub.equals(pub2)) {
      System.out.println("public key verified!");
    } else {
      System.out.println("public key verification failed!");
    }
    dis.close();
    
    // get client's private key
    File f2 = new File("prv.der");
    FileInputStream fis3 = new FileInputStream(f2);
    DataInputStream dis2 = new DataInputStream(fis3);
    byte[] prvBlob = new byte[(int) f2.length()];
    dis2.readFully(prvBlob);
    PrivateKey prv = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(prvBlob));
    dis2.close();
    
    // generate client's nonce
    SecureRandom rand = new SecureRandom();
    byte[] rc = new byte[20];
    rand.nextBytes(rc);

    // 1. send client's certificate
    OutputStream os = client.getOutputStream();
    DataOutputStream dos = new DataOutputStream(os);
    dos.writeInt(cert.getEncoded().length);
    dos.write(cert.getEncoded());
    dos.flush();

    // 3. get server's public key from server's certificate
    BufferedInputStream bis2 = new BufferedInputStream(client.getInputStream());
    DataInputStream dis3 = new DataInputStream(bis2);
    int length = dis3.readInt();
    byte[] pubBlob2 = new byte[length];
    dis3.readFully(pubBlob2);
    InputStream in = new ByteArrayInputStream(pubBlob2);
    CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
    Certificate cert2 = cf2.generateCertificate(in);
    PublicKey pubServer = cert2.getPublicKey();

    // get server's nonce
    BufferedInputStream bis3 = new BufferedInputStream(client.getInputStream());
    DataInputStream dis4 = new DataInputStream(bis3);
    byte[] kcrs = new byte[dis4.readInt()];
    dis4.readFully(kcrs);
    Cipher c = Cipher.getInstance("RSA");
    c.init(Cipher.DECRYPT_MODE, prv);
    byte[] rs = c.doFinal(kcrs);

    // encrypt client's nonce with server's public key and send it
    OutputStream os2 = client.getOutputStream();
    DataOutputStream dos2 = new DataOutputStream(os2);
    Cipher c2 = Cipher.getInstance("RSA");
    c2.init(Cipher.ENCRYPT_MODE, pubServer);
    byte[] ksrc = c2.doFinal(rc);
    dos2.writeInt(ksrc.length);
    dos2.write(ksrc);
    dos2.flush();

    // calculate master secret
    byte[] k = new byte[20];
    int i = 0;
    for (byte b : rs) {
      k[i] = (byte) (b ^ rc[i]);
    }

    // 5. get server's hash1
    BufferedInputStream bis4 = new BufferedInputStream(client.getInputStream());
    DataInputStream dis5 = new DataInputStream(bis4);
    int length2 = dis5.readInt();
    byte[] encrypted1 = new byte[length2];
    dis5.readFully(encrypted1);
    Cipher c3 = Cipher.getInstance("RSA");
    c3.init(Cipher.DECRYPT_MODE, prv);
    byte[] appendedhash1 = c.doFinal(encrypted1);

    byte[] serverString = new byte["SERVER".length()];
    i = 0;
    for (int j = appendedhash1.length - serverString.length; j < appendedhash1.length; ++j) {
      serverString[i++] = appendedhash1[j];
    }
    byte[] serverhash1 = new byte[appendedhash1.length - serverString.length];
    i = 0;
    for (int j = 0; j < serverhash1.length; ++j) {
      serverhash1[i++] = appendedhash1[j];
    }
    if (Arrays.equals(serverString, "SERVER".getBytes())) {
      System.out.println("server string verified!");
    } else {
      System.out.println("server string verification failed!");
    }
    
    // compute and check hash1
    byte[] msg1 = new byte[pubServer.getEncoded().length + rs.length + rc.length + k.length];
    int index = 0;
    System.arraycopy(pubServer.getEncoded(), 0, msg1, index, pubServer.getEncoded().length);
    index += pubServer.getEncoded().length;
    System.arraycopy(rs, 0, msg1, index, rs.length);
    index += rs.length;
    System.arraycopy(rc, 0, msg1, index, rc.length);
    index += rc.length;
    System.arraycopy(k, 0, msg1, index, k.length);
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] hash1 = md.digest(msg1);
//    assert (Arrays.equals(serverhash1, hash1));
    if (Arrays.equals(serverhash1, hash1)) {
      System.out.println("server hash verified!");
    } else {
      System.out.println("server hash verification failed!");
    }
    
    // send client's hash2
    byte[] clientString = "CLIENT".getBytes();
    byte[] appended = new byte[hash1.length + clientString.length];
    System.arraycopy(hash1, 0, appended, 0, hash1.length);
    System.arraycopy(clientString, 0, appended, hash1.length, clientString.length);
    OutputStream os3 = client.getOutputStream();
    DataOutputStream dos3 = new DataOutputStream(os3);
    Cipher c4 = Cipher.getInstance("RSA");
    c4.init(Cipher.ENCRYPT_MODE, pubServer);
    byte[] toSend = c4.doFinal(appended);
    dos3.writeInt(toSend.length);
    dos3.write(toSend);
    dos3.flush();

    // generate secret key
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    random.setSeed(k);
    KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
    keyGenerator.init(random);
    
    SecretKey serverAuthKey = keyGenerator.generateKey();
    SecretKey clientAuthKey = keyGenerator.generateKey();
    SecretKey serverEncKey = keyGenerator.generateKey();
    SecretKey clientEncKey = keyGenerator.generateKey();
    
    System.out.println("handshake successful!");
    
    // 8. get the data from data transfer
    BufferedInputStream bis5 = new BufferedInputStream(client.getInputStream());
    DataInputStream dis6 = new DataInputStream(bis5);
    int length3 = dis6.readInt();
    int length4 = dis6.readInt();
    byte[] transfer = new byte[length4];
    dis6.readFully(transfer);
    byte[] seq = new byte[4];
    System.arraycopy(transfer, 0, seq, 0, 4);
    byte[] encrypted = new byte[transfer.length - 4];
    System.arraycopy(transfer, 4, encrypted, 0, transfer.length - 4);
    Cipher c5 = Cipher.getInstance("DESede");
    c5.init(Cipher.DECRYPT_MODE, serverEncKey);
    byte[] decrypted = c5.doFinal(encrypted);
    byte[] data = new byte[length3];
    System.arraycopy(decrypted, 0, data, 0, length3);
    byte[] tomac = new byte[seq.length + data.length];
    System.arraycopy(seq, 0, tomac, 0, seq.length);
    System.arraycopy(data, 0, tomac, seq.length, data.length);
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(serverAuthKey);
    byte[] hmacClient = mac.doFinal(tomac);
    mac.reset();
    byte[] hmacServer = new byte[hmacClient.length];
    System.arraycopy(decrypted, data.length, hmacServer, 0, hmacServer.length);
    assert(hmacClient.equals(hmacServer));
    File f3 = new File("file.jpg");
    FileOutputStream fos = new FileOutputStream(f3);
    DataOutputStream dos4 = new DataOutputStream(fos);
    dos4.write(data);
    dos4.flush();
    dos4.close();
    System.out.println("\nimage received successfully!");
  }
}