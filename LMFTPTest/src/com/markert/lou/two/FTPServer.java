package com.markert.lou.two;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.*;

public class FTPServer extends Thread{
	//Modified by Lou
    static char lastChar='0';
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = null;
        boolean listening = true;
        //boolean listening = false;
        int serverPort=6666;
	String welcomeMessage="Secure FTP Server V1.0 (Java Version)";
	String passwd=null;
	String root=".";
	if (args.length>=1){
	    root=args[0];
	    if (args.length>=2)	serverPort=Integer.parseInt(args[1]);
	}
	System.out.println(welcomeMessage);
	System.out.println("Usage: java FTPServer [root_directory [port]]");
    	System.out.println("Comments to junhua@cs.nyu.edu or yj3@cs.nyu.edu\n");		
	System.out.print("Please enter your password:");
	passwd=readline();
	File tmp=new File(root);
	root=tmp.getCanonicalPath();
	if (!tmp.isDirectory()) {
	    System.out.println("Directory " + root + " doesn't exist!");
	    System.exit(-1);
	}
	try {
            serverSocket = new ServerSocket(serverPort);
        } catch (IOException e) {
            System.out.println("Could not listen on port: "+serverPort);
            System.exit(-1);
        }
        System.out.println("Server running at port "+serverPort);
	System.out.println("Root directory is: "+root);
        while (listening) {
            new FTPServer(serverSocket.accept(),passwd,welcomeMessage,root).start();
           // new FTPServer(serverSocket.accept(),passwd,welcomeMessage,root).start();
        }
            serverSocket.close();
    }
    static String readline()throws IOException{
    	InputStreamReader stdin=new InputStreamReader(System.in);
    	char[] buf=new char[1024];
    	int i=0;
 	buf[i]=(char)stdin.read();
 	if ((buf[i]=='\n'&&lastChar=='\r')||(buf[i]=='\r'&&lastChar=='\n'))
 	    buf[i]=(char)stdin.read();
    	while(buf[i]!='\n'&&buf[i]!='\r') {
    	    i++;
    	    buf[i]=(char)stdin.read();
    	}
    	lastChar=buf[i];
    	if (i<1) return new String("");
    	else return new String(buf,0,i);    	
    }
    
    Socket socket = null;
    byte[] nonce=null;
    byte[] passwd=null;
    byte[] welcomeMessage=null;
    byte[] hmac=new byte[16];
    DataInputStream in;
    DataOutputStream out;
    MessageDigest md=null;
    MessageDigest md2=null;
    byte[] msg=null;
    String home=null; // Root directory
    String cwd=null;  // Current Working Directory

    FTPServer(Socket socket, String pass, String welcomeMessage, String root) {
	this.socket = socket;
	this.welcomeMessage=welcomeMessage.getBytes();
	this.home=root;
	this.cwd=File.separator;
	this.nonce=this.welcomeMessage;
	this.passwd=getPassword(pass+welcomeMessage);
    }
    byte[] getPassword(String str){
	try{
	    MessageDigest md=MessageDigest.getInstance("SHA-1");
	    return md.digest(str.getBytes());
    	}catch (NoSuchAlgorithmException e){
	    System.out.println("Hash Function SHA-1 Not Found!");
	    return null;
	}
    }
    byte[] getNewNonce(){
    	md2.update(nonce);
    	md2.update(passwd);
    	return md2.digest(((new Date()).toString()).getBytes());
    }
    void send(byte[] msg)throws IOException{  
	// HMAC-server(m)=MD5(m+nonce+passwd)
	// Server send: nonce+msg.length+hmac(msg.length)+msg+hmac(msg)
    	nonce=getNewNonce();
    	out.write(nonce);
    	out.writeInt(msg.length);
    	md.update(Integer.toString(msg.length).getBytes());
    	md.update(nonce);
    	hmac=md.digest(passwd);
    	out.write(hmac);
    	md.update(msg);
    	md.update(nonce);
    	hmac=md.digest(passwd);
    	out.write(msg);
    	out.write(hmac);
    }
    void send(String str)throws IOException{
    	send(str.getBytes());
    }
    int receive()throws IOException{
	// HMAC-client(m)=MD5(m+passwd+nonce)
	// Client send: msg.length+hmac(msg.length)+msg+hmac(msg)
    	int len=in.readInt();
    	in.readFully(hmac);
    	if (!verify(hmac,Integer.toString(len).getBytes(),nonce) || len>1000000) return -1; //hmac failed
    	msg=new byte[len];
    	in.readFully(msg);
    	in.readFully(hmac);
    	if (!verify(hmac,msg,nonce)) return -1;
    	else return len;
    }
    long receiveFile(File file) throws IOException{
  	FileOutputStream fout=new FileOutputStream(file);
   	long len=in.readLong();
   	in.readFully(hmac);
   	if (!verify(hmac,Long.toString(len).getBytes(),nonce)) {
   	    fout.close();
   	    return -1;
   	}
   	byte[] buffer=new byte[4096];
	for (long i=0;i<len/4096;i++){
	    in.readFully(buffer);
	    fout.write(buffer);
	    md.update(buffer);
	}
	int restlen=(int)(len%4096);
	if (restlen>0) {
	    in.readFully(buffer,0,restlen);
	    fout.write(buffer,0,restlen);
	    md.update(buffer,0,restlen);
	}
	fout.close();
	in.readFully(hmac);
	md.update(passwd);
	byte[] hmac2=md.digest(nonce);
	if (MessageDigest.isEqual(hmac,hmac2)) return len;
	else {
	    file.delete();
	    return -1;
	}
    }
    void sendFile(File file)throws IOException{  
    	nonce=getNewNonce();
    	out.write(nonce);
  	FileInputStream fin=new FileInputStream(file);
   	long len=file.length();
    	out.writeLong(len);
    	md.update(Long.toString(len).getBytes());
    	md.update(nonce);
    	hmac=md.digest(passwd);
    	out.write(hmac);
   	byte[] buffer=new byte[4096];
	for (long i=0;i<len/4096;i++){
	    fin.read(buffer);
	    out.write(buffer);
	    md.update(buffer);
	}
	int restlen=(int)(len%4096);
	if (restlen>0) {
	    fin.read(buffer,0,restlen);
	    out.write(buffer,0,restlen);
	    md.update(buffer,0,restlen);
	}
	fin.close();
    	md.update(nonce);
    	hmac=md.digest(passwd);
    	out.write(hmac);
    }
    boolean verify(byte[] hmac, byte[] msg, byte[] nonce){
    	md.update(msg);
    	md.update(passwd);
    	byte[] hmac2=md.digest(nonce);
    	return MessageDigest.isEqual(hmac,hmac2);
    }
    public void run() {
	try {
	    out = new DataOutputStream(socket.getOutputStream());
	    in = new DataInputStream(socket.getInputStream());
	    md=MessageDigest.getInstance("MD5");
	    md2=MessageDigest.getInstance("MD5");	    
	    	    
	    //Shake hands
	    send(welcomeMessage);
	    if (receive()<0){
	    	out.writeBytes("Sorry, I can't recognize you as a legal client");
	    	out.close();
	    	in.close();
	    	socket.close();
	    	System.out.println("Incorrect client from "+socket.getInetAddress()
	    	    +", connection terminated.");
	    	return;
	    }else System.out.println("Client connected from "+socket.getInetAddress());
	    
	    send((new Date())+"  Type ? for help\n");
	    
	    //main loop
	    StringTokenizer st;
	    while(true){
	        if (receive()<0) break;
	        //System.out.println(new String(msg));
	        st=new StringTokenizer(new String(msg));
	        String command;
	        if (st.countTokens()<1) {
	            send("");
	            continue;
	        }
	        command=st.nextToken().toLowerCase();
	        if (command.equals("ls")||command.equals("dir")) dir(st);
	        else if (command.equals("put")) put(st);
	        else if (command.equals("get")) get(st);
	        //else if (command.equals("mput")) mput(st);
	        //else if (command.equals("mget")) mget(st);
	        else if (command.equals("cd")) chdir(st);
	        else if (command.equals("cdup")) cdup();
	        else if (command.equals("pwd")) pwd();
	        else if (command.equals("md") || command.equals("mkdir")) mkdir(st);
	        else if (command.equals("rd") || command.equals("rmdir")) rmdir(st);
	        else if (command.equals("rm") || command.equals("del")) del(st);
	        else if (command.equals("ren") || command.equals("rename")) rename(st);
	        else if (command.equals("?") || command.equals("help")) help();
	        else if (command.equals("quit")||command.equals("bye")||command.equals("close")
	        	 ||command.equals("exit"))break;
	        else send("Unknown command: "+command);
	    }

	    System.out.println("Connection from "+socket.getInetAddress()+" closed.");
	    out.close();
	    in.close();
	    socket.close();
	} catch (Exception e) {
	    System.out.println("Error, close connection.");
	    //e.printStackTrace();
	}
    }
    void help() throws IOException{
    	send("Commands: ls put get cd cdup mkdir rmdir del pwd quit lls lcd help");
    }
    void dir(StringTokenizer st) throws IOException{
    	File tmp=new File(home+cwd);
    	String[] fileList=tmp.list();
    	String msg="Current Directory: "+cwd+"\n";
    	for (int i=0;i<fileList.length;i++) {
    	    tmp=new File(fileList[i]);
    	    //if (tmp.isDirectory()) msg=msg+"<DIR>\t"+fileList[i]+"\n";
    	    if (!tmp.isDirectory()) msg=msg+" "+tmp.length()+"\t"+fileList[i]+"\n";
    	    else msg=msg+"<DIR>\t"+fileList[i]+File.separator+"\n";
    	    //else msg=msg+"\t"+fileList[i]+"\n";
    	}
    	msg=msg+"Total "+fileList.length+" file(s)\n";
    	send(msg);
    }
    void put(StringTokenizer st)throws IOException{
    	if (!st.hasMoreTokens()) send("Error: parameter needed.");
    	else {
    	    String name=st.nextToken();
    	    if (name.startsWith("..")||name.indexOf('\\')>=0||name.indexOf('/')>=0){
   	    	send("Error: syntax error");
   	    }else {
   	    	File tmp=new File(home+cwd+name);
   	    	if (tmp.exists()) send("Error: file exists");
   	    	else {
   	    	    send("OK");
   	    	    if (receiveFile(tmp)>=0) send("File "+name+" transfered to server.");
   	    	    else send("Failed: maybe no permission.");
   	    	}
   	    }	    
	}
    }
    void get(StringTokenizer st) throws IOException{
    	if (!st.hasMoreTokens()) send("Error: parameter needed.");
    	else {
    	    String name=st.nextToken();
    	    if (name.startsWith("..")||name.indexOf('\\')>=0||name.indexOf('/')>=0){
   	    	send("Error: syntax error");
   	    }else {
   	    	File tmp=new File(home+cwd+name);
   	    	if ((!tmp.isFile())||(!tmp.canRead())) send("Error: no such file or permission denied.");
   	    	else {
   	    	    send("OK");
   	    	    if (receive()<0) return;
   	    	    sendFile(tmp);
   	    	}
   	    }	    
	}
    }
    void chdir(StringTokenizer st)throws IOException{
    	String path;
    	if (st.hasMoreTokens()){
    	    path=st.nextToken();
    	    if (!path.startsWith(File.separator)) path=cwd+path;
    	}else path=File.separator;
    	File tmp=new File(home+path);
    	if (tmp.isDirectory()&&tmp.getCanonicalPath().startsWith(home)) {
    	    path=tmp.getCanonicalPath()+File.separator;
    	    cwd=path.substring(home.length(),path.length());
    	    send("Enter Directory: "+cwd+"\n");
    	}else send("Error: directory not exist\n");
    }
    void mkdir(StringTokenizer st) throws IOException{
    	if (!st.hasMoreTokens()) send("Error: parameter needed");
    	else {
    	    String path=st.nextToken();
    	    if (path.startsWith("..")||path.indexOf('\\')>=0||path.indexOf('/')>=0){
    	    	send("Error: format not acceptable");
    	    }else {
    	    	File tmp=new File(home+cwd+path);
    	    	if (tmp.mkdir()) send("Directory "+path+" created.");
    	    	else send("Error: create failed.");
    	    }
    	}
    }
    void rmdir(StringTokenizer st) throws IOException{
    	if (!st.hasMoreTokens()) send("Error: parameter needed");
    	else {
    	    String path=st.nextToken();
    	    if (path.startsWith("..")||path.indexOf('\\')>=0||path.indexOf('/')>=0){
    	    	send("Error: format not acceptable");
    	    }else {
    	    	File tmp=new File(home+cwd+path);
    	    	if (tmp.isDirectory()&& tmp.delete()) send("Directory "+path+" removed.");
    	    	else send("Error: remove failed, permission denied or not empty.");
    	    }
    	}
    }
    void del(StringTokenizer st)throws IOException{
    	if (!st.hasMoreTokens()) send("Error: parameter needed");
    	else {
    	    String path=st.nextToken();
    	    if (path.startsWith("..")||path.indexOf('\\')>=0||path.indexOf('/')>=0){
    	    	send("Error: syntax error");
    	    }else {
    	    	File tmp=new File(home+cwd+path);
    	    	if (tmp.isFile()&&tmp.delete()) send(path+" removed.");
    	    	else send("Error: delete failed.");
    	    }
    	}
    }
    void cdup()throws IOException{
    	File tmp=new File(home+cwd+"..");
    	String path=tmp.getCanonicalPath();
    	if (path.startsWith(home)){
    	    path=path+File.separator;
    	    cwd=path.substring(home.length(),path.length());
    	    send("Enter Directory: "+cwd+"\n");
    	}else send("Operation failed: already root directory\n");
    }
    void pwd()throws IOException{
    	send("Current Directory: "+cwd+"\n");
    }
    void rename(StringTokenizer st)throws IOException{
    	if (st.countTokens()<2) send("Error: 2 parameters needed");
    	else {
    	    String path1=st.nextToken();
    	    String path2=st.nextToken();
    	    if (path1.startsWith("..")||path1.indexOf('\\')>=0||path1.indexOf('/')>=0
    	        ||path2.startsWith("..")||path2.indexOf('\\')>=0||path2.indexOf('/')>=0){
    	    	send("Error: syntax error");
    	    }else {
    	    	File tmp1=new File(home+cwd+path1);
    	    	File tmp2=new File(home+cwd+path2);
    	    	if (tmp1.renameTo(tmp2)) send("Rename succeed.");
    	    	else send("Error: rename failed.");
    	    }
    	}
    }
    void print(byte[] b){
    	for (int i=0;i<b.length;i++) System.out.print(Integer.toHexString(b[i]));
    	System.out.println("");
    }
}