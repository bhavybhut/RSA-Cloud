
import java.math.BigInteger;
import java.net.*; 
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.io.*; 

import javax.crypto.Cipher;
 
class RSAReceiverDecrypt{
	
	private static final String Private_key_Receive = "Private_Key_Receive.key";
	
	 public static void main(String[ ] args){ 
		 try{
			 //get key from generator
			 int filesize=1022386;
		        int bytesRead;
		        int currentTot = 0;
		        InetAddress receiverHost = InetAddress.getLocalHost();
		        Socket socket = new Socket(receiverHost,8989);
		        byte [] bytearray  = new byte [filesize];
		        InputStream is = socket.getInputStream();
		        FileOutputStream fos = new FileOutputStream(Private_key_Receive);
		        BufferedOutputStream bos = new BufferedOutputStream(fos);
		        bytesRead = is.read(bytearray,0,bytearray.length);
		        currentTot = bytesRead;
		 
		        do {
		           bytesRead = is.read(bytearray, currentTot, (bytearray.length-currentTot));
		           if(bytesRead >= 0) currentTot += bytesRead;
		        } while(bytesRead > -1);
		 
		        bos.write(bytearray, 0 , currentTot);
		        bos.flush();
		        bos.close();
		        socket.close();
			 
			 
			 
			 int MAX_LEN = 272; //Because RSA Encryption Buffer Sends 256 bytes
			 int localPortNum = Integer.parseInt("8888");
			 DatagramSocket mySocket = new DatagramSocket(localPortNum);
			 byte[] buffer = new byte[MAX_LEN];
			 DatagramPacket packet = new DatagramPacket(buffer, MAX_LEN);
			 mySocket.receive(packet);
			 //FileOutputStream fos = new FileOutputStream(Private_key_Receive);
			 //fos.write(Arrays.copyOfRange(buffer, 272, MAX_LEN));
			 decryptData(Arrays.copyOfRange(buffer, 8, 264));
			 mySocket.close( );
			 //fos.close();
			 }
			 catch(Exception e) {
				 e.printStackTrace( );
			}
	 }
	 
	 /**
      * Decrypt Data
      * @param data
      * @throws IOException
      */
     private static void decryptData(byte[] data) throws IOException {
             System.out.println("\n----------------DECRYPTION STARTED------------");
             byte[] descryptedData = null;
             
             try {
                     PrivateKey privateKey = readPrivateKeyFromFile(Private_key_Receive);
                     Cipher cipher = Cipher.getInstance("RSA");
                     cipher.init(Cipher.DECRYPT_MODE, privateKey);
                     System.out.println("To be Decrypt Data: " + new String(data));
                     descryptedData = cipher.doFinal(data);
                     System.out.println("Decrypted Data: " + new String(descryptedData));
                     
             } catch (Exception e) {
                     e.printStackTrace();
             }        
             
             System.out.println("----------------DECRYPTION COMPLETED------------");                
     }
     
     /**
      * read Public Key From File
      * @param fileName
      * @return
      * @throws IOException
      */
     public static PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
             FileInputStream fis = null;
             ObjectInputStream ois = null;
             try {
                     fis = new FileInputStream(fileName);
                     ois = new ObjectInputStream(fis);
                     
                     BigInteger modulus = (BigInteger) ois.readObject();
                 BigInteger exponent = (BigInteger) ois.readObject();
                     
                 //Get Private Key
                 RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
                 KeyFactory fact = KeyFactory.getInstance("RSA");
                 PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
                                     
                 return privateKey;
                 
             } catch (Exception e) {
                     e.printStackTrace();
             }
             finally{
                     if(ois != null){
                             ois.close();
                             if(fis != null){
                                     fis.close();
                             }
                     }
             }
             return null;
     }
 }