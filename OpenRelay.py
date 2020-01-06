#
# Before use we need a list of all 25 opened ports :
# nmap -p25 $ip -oA result
# cat result.gnmap | grep open | cut -d " " -f 2 > smtp-open.txt
#
# Write this filename in this python script here :
# `with open('smtp-open.txt') as f:`
#
import socket
import smtplib
from smtplib import *
import logging

logging.basicConfig(filename='openrelay.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s',level=logging.DEBUG)


with open('subnet-prod-ip.txt') as f:
   for line in f:
	# there may be a CR reading the file, so we remove it
        IP = line.strip('\n')
        Port = "25"
	X = "nobody@nowhere.ch"
	Y = "tester@domain.ch"

	s = socket.socket()
	logging.info('[-] Connexion to : ' + IP)
	print "\n[-] Connexion to : " + IP
	try:
		s.connect((IP,int(Port)))
		socket.setdefaulttimeout(6)
	
		ans = s.recv(1024)


		if ("220" in ans):
		    print "\n[+] Port" + " " + str(Port) + " " + "open on the target system\n"
		    logging.info('[+] Port' + ' ' + str(Port) + ' ' + 'open on the target system')
		    smtpserver = smtplib.SMTP(IP,int(Port))
		    h = smtpserver.docmd("EHLO ",IP)
		    a = str(h)
                    # if the server prefer HELO
                    if ("502" in a):
			logging.info('EHLO refused, sending HELO')
                        h = smtpserver.docmd("HELO ",IP)

		    r = smtpserver.docmd("Mail From:",X)
		    a = str(r)
		    logging.info(a)

		    if ("250" in a):
		        r = smtpserver.docmd("RCPT TO:",Y)
		        a = str(r)
			logging.info(a)
		        if ("250" in a):
            
		            print "[+] The target system seems vulenarble to Open relay attack"
			    logging.info('[+] ' + IP + ' system seems vulenarble to Open relay attack')

			    r = smtpserver.docmd("DATA")
			    a = str(r)
			    logging.info(a)
			    r = smtpserver.docmd("Hello from" + IP + "\r\n.\r\n")
			    a = str(r)
			    logging.info(a)
			    if ("250" in a):
				    logging.info('[+] ' + IP + ' permet de relayer des mails')
			

		        elif ("Unable to relay" in a) or ("unable to relay" in a) or ("Relay access denied" in a) or ("Authentication required to relay" in a) or ("Relay denied" in a):
                            print "[-] The target system is unable to relay"
                            logging.info('[-] ' + IP + ' system is unable to relay')


			else:
		            print "[-] The target system is not vulnerable to Open relay attack "
			    logging.info('[-] ' + IP + ' is not vulnerable to Open relay attack')

    
		    elif ("553" in a):
                            print "[-] Sender rejected"
                            logging.info('[-] ' + IP + ' Sender rejected')


		else:
		    print "[-] Port is closed/Filtered"
		    logging.info('[-] Port is closed/Filtered')
	except socket.error, exc:
		print "Caught exception socket.error : %s" % exc
		logging.info('Caught exception socket.error : %s' % exc)

	logging.info('-------------------------------------------------------')
	logging.info(' ')
	#raw_input("Press Enter to continue...")
