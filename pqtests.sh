#!/bin/bash

# Sample validation-only invocation
# VAL_ONLY=1 bash ~/Desktop/pqtests.sh ~/Desktop/unpacked/snakefoot_new2/

create_folder_and_move_files() {
	set +x
	rm -rf $target_folder
	mkdir $target_folder
	mkdir $target_folder/ta
	mkdir $target_folder/ca
	mkdir $target_folder/ee
	mkdir $target_folder/crl
	mv $certs_folder/shared_ta.crl $target_folder/crl/crl_ta.crl
	mv $certs_folder/shared_ca.crl $target_folder/crl/crl_ca.crl
	mv $certs_folder/shared_ta.der $target_folder/ta/ta.der
	mv $certs_folder/shared_ta.oak $target_folder/ta/ta_priv.oak
	mv $certs_folder/shared_ca.der $target_folder/ca/ca.der
	mv $certs_folder/shared_ca.oak $target_folder/ca/ca_priv.oak
	mv $certs_folder/cert.der $target_folder/ee/cert.der 
	mv $certs_folder/cert_priv.oak $target_folder/ee/cert_priv.oak
	mv $csrs_folder/cert.csr $target_folder/ee/cert.csr  
	mv $certs_folder/shared_ta.pem $target_folder/ta/ta.pem
	mv $certs_folder/ta_priv.pem $target_folder/ta/ta_priv.pem
	mv $certs_folder/shared_ca.pem $target_folder/ca/ca.pem
	mv $certs_folder/shared_ca_priv.pem $target_folder/ca/ca_priv.pem
	mv $certs_folder/cert.pem $target_folder/ee/cert.pem 
	mv $certs_folder/cert_priv.pem $target_folder/ee/cert_priv.pem  
	if [ ! -z $DBG ]
	then
		set -x
	fi
}

certgen="./target/release/certgen"
pittv3="../rust-pki/target/release/pittv3"
pittv3_log_cfg=./log.yaml

csrs_folder="./csrs"
if [ ! -d "csrs_folder" ]
  then
    mkdir $csrs_folder
fi

if [ ! -z $1 ]
then
	VAL_ONLY=1
	certs_folder=$1
else
	certs_folder="./artifacts"
  if [ ! -d "$certs_folder" ]
    then
    mkdir $certs_folder
  fi
fi

if [ ! -f "$certgen" ]
	then
		echo "Could not find certgen" 1>&2
		exit 1
fi
if [ ! -f "$pittv3" ]
	then
		echo "Could not find $pittv3" 1>&2
		exit 1
fi

if [ ! -d "$certs_folder" ]
	then
		echo "Could not find $certs_folder" 1>&2
		exit 1
fi


ECDSA_P256_PK="1.2.840.10045.3.1.7"
ECDSA_P256_SIG="1.2.840.10045.4.3.2"

OQ_Dilithium2="1.3.6.1.4.1.2.267.7.4.4"
OQ_Dilithium3="1.3.6.1.4.1.2.267.7.6.5"
OQ_Dilithium5="1.3.6.1.4.1.2.267.7.8.7"
OQ_DilithiumAES2="1.3.6.1.4.1.2.267.11.4.4"
OQ_DilithiumAES3="1.3.6.1.4.1.2.267.11.6.5"
OQ_DilithiumAES5="1.3.6.1.4.1.2.267.11.8.7"
OQ_FALCON_512="1.3.9999.3.1"
OQ_FALCON_1024="1.3.9999.3.4"
OQ_SPHINCSp_SHA256_128f_robust="1.3.9999.6.4.1"
OQ_SPHINCSp_SHA256_128f_simple="1.3.9999.6.4.4"
OQ_SPHINCSp_SHA256_128s_robust="1.3.9999.6.4.7"
OQ_SPHINCSp_SHA256_128s_simple="1.3.9999.6.4.10"
OQ_SPHINCSp_SHA256_192f_robust="1.3.9999.6.5.1"
OQ_SPHINCSp_SHA256_192f_simple="1.3.9999.6.5.3"
OQ_SPHINCSp_SHA256_192s_robust="1.3.9999.6.5.5"
OQ_SPHINCSp_SHA256_192s_simple="1.3.9999.6.5.7"
OQ_SPHINCSp_SHA256_256f_robust="1.3.9999.6.6.1"
OQ_SPHINCSp_SHA256_256f_simple="1.3.9999.6.6.3"
OQ_SPHINCSp_SHA256_256s_robust="1.3.9999.6.6.5"
OQ_SPHINCSp_SHA256_256s_simple="1.3.9999.6.6.7"
ENTU_Dilithium2="2.16.840.1.114027.80.3.2.1"
ENTU_Dilithium3="2.16.840.1.114027.80.3.2.2"
ENTU_Dilithium5="2.16.840.1.114027.80.3.2.3"
ENTU_DilithiumAES2="2.16.840.1.114027.80.3.2.4"
ENTU_DilithiumAES3="2.16.840.1.114027.80.3.2.5"
ENTU_DilithiumAES5="2.16.840.1.114027.80.3.2.6"
ENTU_FALCON_512="2.16.840.1.114027.80.3.3.1"
ENTU_FALCON_1024="2.16.840.1.114027.80.3.3.2"

ENTU_COMPOSITE_SIG="1.3.6.1.4.1.18227.2.1"
ENTU_COMPOSITE_KEY="2.16.840.1.114027.80.4.1"
ENTU_DILITHIUM3_ECDSA_P256="2.16.840.1.114027.80.5.1"
ENTU_DILITHIUM3_RSA="2.16.840.1.114027.80.5.2"

composite_algs_sig1=($ECDSA_P256_SIG $ECDSA_P256_SIG $OQ_Dilithium3)
composite_algs_pk1=($ECDSA_P256_PK $ECDSA_P256_PK $OQ_Dilithium3)
composite_algs_sig2=($OQ_Dilithium3 $OQ_Dilithium2 $ECDSA_P256_SIG)
composite_algs_pk2=($OQ_Dilithium3 $OQ_Dilithium2 $ECDSA_P256_PK)
composite_algs_sig3=($OQ_FALCON_512 $OQ_FALCON_1024)
composite_algs_pk3=($OQ_FALCON_512 $OQ_FALCON_1024)
composite_sig=($ENTU_COMPOSITE_SIG $ENTU_COMPOSITE_SIG $ENTU_COMPOSITE_SIG)
composite_pk=($ENTU_COMPOSITE_KEY $ENTU_COMPOSITE_KEY $ENTU_DILITHIUM3_ECDSA_P256)

classical_algs_sig=($ECDSA_P256_SIG)
classical_algs_pk=($ECDSA_P256_PK)
pqc_algs=($OQ_Dilithium2 $OQ_Dilithium3 $OQ_Dilithium5 $OQ_FALCON_512 $OQ_FALCON_1024 $OQ_DilithiumAES2 $OQ_DilithiumAES3 $OQ_DilithiumAES5 $OQ_SPHINCSp_SHA256_128f_robust $OQ_SPHINCSp_SHA256_128f_simple $OQ_SPHINCSp_SHA256_128s_robust $OQ_SPHINCSp_SHA256_128s_simple $OQ_SPHINCSp_SHA256_192f_robust $OQ_SPHINCSp_SHA256_192f_simple $OQ_SPHINCSp_SHA256_192s_robust $OQ_SPHINCSp_SHA256_192s_simple $OQ_SPHINCSp_SHA256_256f_robust $OQ_SPHINCSp_SHA256_256f_simple $OQ_SPHINCSp_SHA256_256s_robust $OQ_SPHINCSp_SHA256_256s_simple)

set +x
if [ ! -z $C2_ONLY ]
then
	SKIP_PQC=1
	SKIP_C3=1
	SKIP_CLA=1
fi
if [ ! -z $C3_ONLY ]
then
	SKIP_C2=1
	SKIP_PQC=1
	SKIP_CLA=1
fi
if [ ! -z $CLA_ONLY ]
then
	SKIP_C2=1
	SKIP_C3=1
	SKIP_PQC=1
fi

if [ ! -z $PQC_ONLY ]
then
	SKIP_C2=1
	SKIP_C3=1
	SKIP_CLA=1
fi

if [ ! -z $DBG ]
then
	set -x
fi

if [ -z $SKIP_C2 ]
then
	for i in "${!composite_algs_sig1[@]}"; do
		if [ "$ENTU_COMPOSITE_KEY" == "${composite_pk[i]}" ]
		then
			alg="${composite_algs_pk1[i]}_${composite_algs_pk2[i]}"
		else
			alg="${composite_pk[i]}"
		fi	
		target_folder=$certs_folder/$alg

		if [ -z $VAL_ONLY ]
		then
			echo "Generating certificates for $alg"
			$certgen -s $certs_folder -c $csrs_folder --generate-ca-signed-certs  -n 1 -m 1 -i 1 --pk-alg1 ${composite_algs_pk1[i]} --sig-alg1 ${composite_algs_sig1[i]} --pk-alg2 ${composite_algs_pk2[i]} --sig-alg2 ${composite_algs_sig2[i]} --composite-pk ${composite_pk[i]} --composite-sig ${composite_sig[i]}
			create_folder_and_move_files
		fi
		echo "Validating certificates for $alg"
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -c $certs_folder/$alg/ca --generate -l $pittv3_log_cfg
		$pittv3 -t $certs_folder/$alg/ta -b $certs_folder/$alg/$alg.cbor --list-partial-paths
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -f $certs_folder/$alg/ee -s $certs_folder/default.json --crl-folder $certs_folder/$alg/crl
		$echo
	done
else
	echo "Skipping composite with two algorithms"
fi

if [ -z $SKIP_C3 ]
then
	for i in "${!composite_algs_sig3[@]}"; do
		if [ "$ENTU_COMPOSITE_KEY" == "${composite_pk[i]}" ]
		then
			alg="${composite_algs_pk1[i]}_${composite_algs_pk2[i]}_${composite_algs_pk3[i]}"
		else
			alg="${composite_pk[i]}"
		fi	
		target_folder=$certs_folder/$alg

		if [ -z $VAL_ONLY ]
		then
			echo "Generating certificates for $alg"
			$certgen -s $certs_folder -c $csrs_folder --generate-ca-signed-certs  -n 1 -m 1 -i 1 --pk-alg1 ${composite_algs_pk1[i]} --sig-alg1 ${composite_algs_sig1[i]} --pk-alg2 ${composite_algs_pk2[i]} --sig-alg2 ${composite_algs_sig2[i]} --pk-alg3 ${composite_algs_pk3[i]} --sig-alg3 ${composite_algs_sig3[i]} --composite-pk $ENTU_COMPOSITE_KEY --composite-sig $ENTU_COMPOSITE_SIG
			create_folder_and_move_files
		fi
		echo "Validating certificates for $alg"
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -c $certs_folder/$alg/ca --generate -l $pittv3_log_cfg
		$pittv3 -t $certs_folder/$alg/ta -b $certs_folder/$alg/$alg.cbor --list-partial-paths
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -f $certs_folder/$alg/ee -s $certs_folder/default.json --crl-folder $certs_folder/$alg/crl
		$echo
	done
else
	echo "Skipping composite with three algorithms"
fi

if [ -z $SKIP_CLA ]
then
	for i in "${!classical_algs_pk[@]}"; do
		alg=${classical_algs_pk[i]}
		target_folder=$certs_folder/$alg

		if [ -z $VAL_ONLY ]
		then
			echo "Generating certificates for $alg"
			$certgen -s $certs_folder -c $csrs_folder --generate-ca-signed-certs  -n 2 -m 2 -i 2 --pk-alg1 ${classical_algs_pk[i]} --sig-alg1 ${classical_algs_sig[i]}
			create_folder_and_move_files
		fi
		echo "Validating certificates for $alg"
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -c $certs_folder/$alg/ca --generate -l $pittv3_log_cfg
		$pittv3 -t $certs_folder/$alg/ta -b $certs_folder/$alg/$alg.cbor --list-partial-paths
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -f $certs_folder/$alg/ee -s $certs_folder/default.json --crl-folder $certs_folder/$alg/crl
		$echo
	done
else
	echo "Skipping classical algorithms"
fi

if [ -z $SKIP_PQC ]
then
	for alg in ${pqc_algs[@]}; do
		target_folder=$certs_folder/$alg

		if [ -z $VAL_ONLY ]
		then
			echo "Generating certificates for $alg"
			$certgen -s $certs_folder -c $csrs_folder --generate-ca-signed-certs  -n 2 -m 2 -i 2 --pk-alg1 $alg --sig-alg1 $alg
			create_folder_and_move_files
		fi
		echo "Validating certificates for $alg"
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -c $certs_folder/$alg/ca --generate -l $pittv3_log_cfg
		$pittv3 -t $certs_folder/$alg/ta -b $certs_folder/$alg/$alg.cbor --list-partial-paths
		$pittv3 -b $certs_folder/$alg/$alg.cbor -t $certs_folder/$alg/ta -f $certs_folder/$alg/ee -s $certs_folder/default.json --crl-folder $certs_folder/$alg/crl
		$echo
	done
else
	echo "Skipping PQ algorithms"
fi

if [ ! -z $DBG ]
then
	set +x
fi
