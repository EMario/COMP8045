ip=192.168.1.
i=0
max=200
n=21

while [ $i -lt $max ]
do
	res=$(($i+$n))
	arp -s $ip$res 00:32:03:44:91:34
	true $(( i++ ))
done
