﻿# Blockchain_Ledger_Project

 ## Run instructions
 1) Run the Makefile by issuing the commands
     * *make clean*
     * *make*
 3) Run *./cryptomoney.sh* to execute blockchain_program.py with any flags you would like to provide. The flags you can use with the Shell script is detailed below.

## Flags to run program
* -name : The name of the cryptocurrency exchange
* -generate <filename_for_wallet.txt> : To generate a wallet under a certain filename
* -address <filename_for_wallet.txt> : To print the tag of the wallet provided (each wallet has a private key and public key). The signature or hash of the public key is the tag of unique identifier of the wallet
* -fund <tag of wallet to fund to> <amount to fund> <name_of_fund_record_file.txt> : All funds go through a "funder" or distributer. This flag distributes the <amount to fund> to the wallet associated with the tag provided and stores it in a fund record file.
* -transfer <source_wallet_file.txt> <destination tag> <amount to transfer> <transfer_request_file.txt> : Transfer some amount from the source wallet to the destination wallet (using the tag of the wallet). The transfer will be recorded in a block in the blockchain which contains the hash of all previous blocks to maintain the integrity of the existence of the transfer.
* -balance <tag of wallet> : returns balance of the wallet associated with the given tag
* -mine : Roughly simulate mining in a blockchain.
