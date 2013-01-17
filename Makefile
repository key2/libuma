


all:
	gcc -g -ggdb uma_msg.c tlv.c main.c -o imsi_loc
	gcc -g -ggdb -losmocore -losmogsm decode_submit.c osmocom_helper.c uma_msg.c tlv.c client.c -o rogue_client

clean:
	rm -f *.o rogue_client imsi_loc
