# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v1.1
# Released under GPL Version 2 license.
# Use at your own risk

if [[ -n $1 && -n $2 && -n $3 ]] #not provide enough parameters to launch carbonator
then
	STATE=$1
	SCHEME=$2
	FQDN=$3
	PORT=$4
	if [[ -n $5 ]]
	then
		FOLDER=$5
	fi

	if [[ -n $6 ]]
	then
		EMAIL=$6
		echo Launching Scan against $1://$2:$3$4 EMailing reports to $6
		java -jar -Xmx1024m C:/Users/ryan.a.perrizo/burpsuite_pro_v1.6.24.jar $STATE $SCHEME $FQDN $PORT $FOLDER
		echo 'Your scan results are attached to this email. Please visit https://www.integrissecurity.com/index.php?resources=Carbonator for more information.' | mutt -s 'Integris Security Carbonator Results' $6 -a IntegrisSecurity_Carbonator_$1_$2_$3.html && rm IntegrisSecurity_Carbonator_$1_$2_$3.html
	else
		echo Launching Scan against $2://$3:$4$5
		java -jar -Xmx20g C:/Users/ryan.a.perrizo/burpsuite_pro_v1.6.24.jar $STATE $SCHEME $FQDN $PORT $FOLDER
	fi
else
	echo Usage: $0 scheme fqdn port path email
	echo '    'Example: $0 http localhost 80 /folder carbonator@integrissecurity.com
	echo '    Scan multiple sites: cat scheme_fqdn_port.txt | xargs -L1 '$0
fi

exit
