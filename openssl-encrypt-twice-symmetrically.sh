#!/bin/bash
# Open source. GPL3 license. Use as you like. No warranty. No claims.
# Not liable. Not responsible for losses or damages.
# https://www.gnu.org/licenses/gpl-3.0.en.html

# If this software does not suit you, here are some alternative pieces of
# software that are very similar:
# scrypt https://www.tarsnap.com/scrypt.html
# age https://github.com/FiloSottile/age
# rage https://github.com/str4d/rage
# https://github.com/SixArm/gpg-encrypt
# https://github.com/SixArm/gpg-decrypt
# https://github.com/SixArm/openssl-encrypt
# https://github.com/SixArm/openssl-decrypt
# https://github.com/vsencrypt/vsencrypt
# https://github.com/8go/gpg-openssl-encrypt-twice-symmetrically

# Difference between gpg-encrypt-twice-symmetrically and openssl-encrypt-twice-symmetrically:
# 1) different ciphers: Chacha20 vs TwoFish
#    - gpg variant uses first AES256 and then TwoFish
#    - openssl variant uses first Chacha20 and then AES256
# 2) different amount of iterations of password hashing
#    - higher in openssl variant --> slows attacker down
# 3) number of iterations of password hashing recall
#    - gpg variant stores it in encrypted file, so not needed on decryption
#    - with openssl variant you need to know/remember this number in order to decrypt!
# 4) resulting file sizes
#    - gpg variant output file sizes are slightly larger
#    - for a plaintext of 347 bytes, openssl variant produced an output of 520 bytes,
#      gpg variant an output of 752 bytes
# Remember: both variants are ONLY secure if the two passwords are difficult,
#    - using easy password will lead to easy-to-break results

FILEEXTENSION="enc"
FILEEXTENSION_TMP="tmp.enc"
FILEEXTENSION_HASH="sha"
FILEEXTENSION_INFO="inf"
FILEEXTENSION_QR_PNG="png" # QR image
FILEEXTENSION_QR_SVG="svg" # QR image
FILENAME="ciphertext"      # filename for enc output if stdin is used

PLAINNAME="plaintext.txt" # filename for output if encrypted file has no extension
TMP="tmp"                 # to indicate temporary file
MAX_FILESIZE_FOR_QR=4096  # if the output file is larger than that no QR code will be produced
UMASK_ORIGINAL=$(umask)   # the original umask value, for later restoring
UMASK_READONLY="0377"     # created files (will be r--)
# SHA_HASH_ITERATIONS: -iter default is 1,000 (known to be weak)
# SHA_HASH_ITERATIONS: -iter recommended is 100,000 to 1,000,000
# SHA_HASH_ITERATIONS: -iter 100,000,000 roughly 1 min on basic average 2020 CPU, tested
# SHA_HASH_ITERATIONS: -iter 1,000,000,000 roughly 10 min on basic average 2020 CPU, tested
# to calculate time run: openssl speed sha512   .... and look at the 256 block size
# We don't use a round number like 100000000 just in case there is or
# will be a rainbow table for round numbers of hahes like 100000000.
SHA_HASH_ITERATIONS_RECOMMENDED=100000017            # 100M
SHA_HASH_ITERATIONS=$SHA_HASH_ITERATIONS_RECOMMENDED # 100M
# SHA_HASH_ITERATIONS=100000                         # 100K # for testing only
HASHING_TIME_IN_SEC=$(expr $SHA_HASH_ITERATIONS / 1666666) # estimate for moderate CPU in 2020
SHRED_ROUNDS=10                                            # default is 3
# If this file exists in local directory use it as source of password for AES encryption
PASSPHRASE_FILE_AES_FILE="passphrase-file-aes" # no spaces please
PASSPHRASE_FILE_AES_OPTION="-pass file:$PASSPHRASE_FILE_AES_FILE"
# If this file exists in local directory use it as source of password for Chacha20 encryption
PASSPHRASE_FILE_CHACHA_FILE="passphrase-file-chacha" # no spaces please
PASSPHRASE_FILE_CHACHA_OPTION="-pass file:$PASSPHRASE_FILE_CHACHA_FILE"

# usage: outputs to stdout the --help usage message.
usage() {
  echo "${0##*/}: Version: v2020-11-02"
  echo "${0##*/}: Usage: ${0##*/} [--help] [--encrypt|--decrypt] files"
  echo "${0##*/}: e.g. ${0##*/} file1.txt file2.jpg # encrypt 2 files"
  echo "${0##*/}: e.g. ${0##*/} # read from stdin, encrypt text from stdin input"
  echo "${0##*/}: e.g. ${0##*/} --encrypt file1.txt file2.jpg # encrypt 2 files"
  echo "${0##*/}: e.g. ${0##*/} --encrypt # read from stdin, encrypt text from stdin input"
  echo "${0##*/}: e.g. ${0##*/} --decrypt file1.txt.enc file2.jpg.enc # decrypt 2 files"
  echo "${0##*/}: By default, if not specified, script assumes --encrypt"
  echo "${0##*/}: If you want to decrypt you must specify: --decrypt"
  echo "${0##*/}: If used, --encrypt or --decrypt must be the FIRST argument."
  echo "${0##*/}: "
  echo "${0##*/}: Script encrypts specified files SYMMETRICALLY (no key, just password) "
  echo "${0##*/}: appending $FILEEXTENSION to file name."
  echo "${0##*/}: It uses openssl to first encrypt with cipher Chacha20."
  echo "${0##*/}: Then it uses openssl to encrypt a second time with cipher AES-256-cbc."
  echo "${0##*/}: As a last step, openssl is used to compute a 512-bit hash."
  echo "${0##*/}: If no file is provided as command line argument, script will read "
  echo "${0##*/}: plain-text from std input."
  echo "${0##*/}: "
  echo "${0##*/}: If a file named \"$PASSPHRASE_FILE_CHACHA_FILE\" exists in the local"
  echo "${0##*/}: directory, then it will be used as passphrase source instead of stdin"
  echo "${0##*/}: for the Chacha20-round (first round) of encryption."
  echo "${0##*/}: "
  echo "${0##*/}: If a file named \"$PASSPHRASE_FILE_AES_FILE\" exists in the local"
  echo "${0##*/}: directory, then it will be used as passphrase source instead of stdin"
  echo "${0##*/}: for the AES-round (second round) of encryption."
  echo "${0##*/}: "
  echo "${0##*/}: TLDR: The whole encryption script in a nutshell does only 3 lines of code:"
  echo "${0##*/}: command 1: openssl enc -e -chacha20 -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 -in \"plaintext\" -out \"plaintext.tmp.enc\""
  echo "${0##*/}: command 2: openssl enc -e -aes-256-cbc -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 -base64 -in \"plaintext.tmp.enc\" -out \"plaintext.enc\""
  echo "${0##*/}: command 3: openssl dgst -sha512 -out \"plaintext.sha\" \"plaintext.enc\""
  echo "${0##*/}: "
  echo "${0##*/}: Decrypt does the opposite. It recovers the plaintext from the ciphertext."
  echo "${0##*/}: TLDR: The whole decryption script in a nutshell does the 3 lines of code from above in the reverse order but with -d instead of -e."
  echo ""
  if [ "$DEBUG" == "true" ]; then
    echo ""
    echo "Typical encryption process looks similar to this: "
    cat << END
$ ./${0##*/}
${0##*/}: Install latest version of "openssl", "shred" and "qrencode"!
${0##*/}: It will NOT overwrite files. So, if you run it twice it will give error.
${0##*/}: Remove old files manually first if you run script twice.
${0##*/}: No input file provided. Will read plaintext from stdin (keyboard).
${0##*/}: 3 Steps:
${0##*/}:   Step 1: Will ask twice for Chacha20 password.
${0##*/}:   Step 2: Will ask for plaintext (text you want to encrypt). There is NO prompt.
${0##*/}:           Terminate input with Ctrl-D as first letter in new line.
${0##*/}:   Step 3: Will ask twice for AES password.
enter chacha20 encryption password:
Verifying - enter chacha20 encryption password:
My secret text here...
${0##*/}: Success: openssl encrypted file - successfully.
enter aes-256-cbc encryption password:
Verifying - enter aes-256-cbc encryption password:
${0##*/}: Success: openssl encrypted file ciphertext.tmp.enc successfully.
${0##*/}: Success: shred shredded temporary file ciphertext.tmp.enc successfully.
${0##*/}: ciphertext output in file "ciphertext.enc"
${0##*/}: Success: openssl hashed file ciphertext.enc successfully.
${0##*/}: sha512 hash of ciphertext output in file "ciphertext.sha"
SHA512(ciphertext.enc)= 39aa276cd2243b706a5380fe115644f0733e269facc3860bd1aaa583f7d24408c2d1b2e77c3676f301ce21d7b28837f8236edf9ee679f27e28ca1b42e966db73
${0##*/}: Success: qrencode produced QR code for file ciphertext.enc successfully.
${0##*/}: QR codes are in files "ciphertext.png" and "ciphertext.svg"
${0##*/}: Meta data is in file "ciphertext.inf"
${0##*/}: SUCCESS! Look at ciphertext output in file "ciphertext.enc".
END
  fi
} # usage()

# takes 1 optional argument, the return value, the exit value
cleanup_exit() {
  echo "${0##*/}: Cleaning up."
  # cleanup
  umask "$UMASK_ORIGINAL" # return to previous state
  # exit
  if [ "$#" -gt "0" ]; then
    if [ "$1" -ne "0" ]; then
      echo "${0##*/}: Exiting with error (code $1)."
    else
      echo "${0##*/}: Exiting with success."
    fi
    exit $1
  else
    echo "${0##*/}: Exiting with interrupt."
    exit 20
  fi
}

# 1 argument: word "encryption" or "decryption" for echo, debug message
# used by both: encrypt and decrypt
read-passphrase-files-if-availble() {
  # check if certain files DO exist
  if [ -f "$PASSPHRASE_FILE_CHACHA_FILE" ]; then
    echo "${0##*/}: Info: Found file \"$PASSPHRASE_FILE_CHACHA_FILE\". It will be used as source for the Chacha20 passphrase. You will not be asked for a passphrase for Chacha20 $1."
  else
    echo "${0##*/}: Info: File \"$PASSPHRASE_FILE_CHACHA_FILE\" not found. It cannot be used as source for the Chacha20 passphrase. You will be asked for a passphrase for Chacha20 $1."
    PASSPHRASE_FILE_CHACHA_OPTION="" # don't use this option
  fi
  if [ -f "$PASSPHRASE_FILE_AES_FILE" ]; then
    echo "${0##*/}: Info: Found file \"$PASSPHRASE_FILE_AES_FILE\". It will be used as source for the AES passphrase. You will not be asked for a passphrase for AES $1."
  else
    echo "${0##*/}: Info: File \"$PASSPHRASE_FILE_AES_FILE\" not found. It cannot be used as source for the AES passphrase. You will be asked for a passphrase for AES $1."
    PASSPHRASE_FILE_AES_OPTION="" # don't use this option
  fi
}

# encryptSymmetricDouble():
# takes 0 arguments --> read from stdin, encrypt text from stdin
# takes 1 argument --> file name, encrypt file
encryptSymmetricDouble() {
  if [ "$#" -eq "0" ]; then # no argument given
    infile="-"
    outfile="$FILENAME"
  else
    infile="$1"
    outfile="$1"
    if [ ! -f "$infile" ]; then
      echo "${0##*/}: ERROR: file \"$infile\" does not exist or is not a file. Aborting. "
      cleanup_exit 22
    fi
  fi
  outfile1="${outfile}.$FILEEXTENSION"
  outfileT="${outfile}.$FILEEXTENSION_TMP"
  outfile2="${outfile}.$FILEEXTENSION_HASH"
  outfile3="${outfile}.$FILEEXTENSION_QR_PNG"
  outfile4="${outfile}.$FILEEXTENSION_QR_SVG"
  outfile5="${outfile}.$FILEEXTENSION_INFO"

  # make sure certain files do NOT exist
  for afile in "$outfileT" "$outfile1" "$outfile2" "$outfile3" "$outfile4" "$outfile5"; do
    if [ -e "$afile" ]; then
      echo "${0##*/}: ERROR: file \"$afile\" does already exist. Not overwriting it. Aborting. "
      cleanup_exit 23
    fi
  done
  # check if certain files DO exist
  read-passphrase-files-if-availble "encryption"

  # set expectations
  if [ "$PASSPHRASE_FILE_CHACHA_OPTION" == "" ]; then
    echo "${0##*/}: First Step : Will ask twice for Chacha20 password."
  fi
  if [ "$#" -eq "0" ]; then # no argument given
    echo "${0##*/}: Next Step  : Will ask for plaintext (text you want to encrypt). There is NO prompt. "
    echo "${0##*/}:              Terminate input with Ctrl-D as first letter in new line."
  fi
  if [ "$PASSPHRASE_FILE_AES_OPTION" == "" ]; then
    echo "${0##*/}: Next Step  : Will ask twice for AES256 password."
  fi
  echo "${0##*/}: Be patient. Password hashing takes more than $HASHING_TIME_IN_SEC seconds each. So wait."

  # Don't do: openssl enc -e -chacha20 ... -in "$infile" | openssl enc -e -aes-256-cbc ... -out "$outfile1"
  command1='openssl enc -e -chacha20 -salt -pbkdf2 -iter '$SHA_HASH_ITERATIONS' -md sha512 '$PASSPHRASE_FILE_CHACHA_OPTION' -in "'$infile'" -out "'$outfileT'"'
  echo "${0##*/}: Starting command: $command1"
  openssl enc -e -chacha20 -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 $PASSPHRASE_FILE_CHACHA_OPTION -in "$infile" -out "$outfileT" # No -base64 here!
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not encrypt file \"$infile\". Aborting."
    cleanup_exit 10
  else
    echo "${0##*/}: Success: openssl encrypted file \"$infile\" successfully."
  fi
  command2='openssl enc -e -aes-256-cbc -salt -pbkdf2 -iter '$SHA_HASH_ITERATIONS' -md sha512 '$PASSPHRASE_FILE_AES_OPTION' -base64 -in "'$outfileT'" -out "'$outfile1'"'
  echo "${0##*/}: Starting command: $command2"
  openssl enc -e -aes-256-cbc -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 $PASSPHRASE_FILE_AES_OPTION -base64 -in "$outfileT" -out "$outfile1" # Yes, -base64 here
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not encrypt file \"$outfileT\". Aborting."
    cleanup_exit 11
  else
    echo "${0##*/}: Success: openssl encrypted file \"$outfileT\" successfully."
  fi
  chmod 600 "$outfileT"
  shred --iterations=$SHRED_ROUNDS --zero --remove "$outfileT"
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: Warning: shred returned error \"$ret\". shred could not shred file \"$outfileT\". Is \"shred\" installed? No problem, instead of shredding we will just remove it."
    rm "$outfileT"
  else
    echo "${0##*/}: Success: shred shredded temporary file \"$outfileT\" successfully."
  fi
  # chmod 400 "$outfile1" # using umask instead
  command3='openssl dgst -sha512 -out "'$outfile2'" "'$outfile1'"'
  echo "${0##*/}: Starting command: $command3"
  echo "${0##*/}: ciphertext output in file \"$outfile1\""
  openssl dgst -sha512 -out "$outfile2" "$outfile1"
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not hash file \"$outfile1\"."
  else
    echo "${0##*/}: Success: openssl hashed file \"$outfile1\" successfully."
  fi
  echo "${0##*/}: sha512 hash of ciphertext output in file \"$outfile2\""
  # chmod 400 "$outfile2"  # using umask instead
  cat $outfile2
  filesize=$(du -b "$outfile1" | xargs | cut -d " " -f 1)
  if [ "$filesize" -le "$MAX_FILESIZE_FOR_QR" ]; then
    qrencode --level=M --margin=4 --size=10 --dpi=72 --type=PNG --output="$outfile3" --read-from="$outfile1"
    ret=$?
    if [ "$ret" -ne "0" ]; then
      echo "${0##*/}: ERROR: qrencode returned error \"$ret\". qrencode could not create QR code for file \"$outfile1\". We continue without producing a PNG QR code."
    else
      echo "${0##*/}: Success: qrencode produced QR code for file \"$outfile1\" successfully. See \"$outfile3\"."
    fi
    qrencode --level=M --margin=4 --size=10 --dpi=72 --type=SVG --output="$outfile4" --read-from="$outfile1"
    ret=$?
    if [ "$ret" -ne "0" ]; then
      echo "${0##*/}: ERROR: qrencode returned error \"$ret\". qrencode could not create QR code for file \"$outfile1\". We continue without producing an SVG QR code."
    else
      echo "${0##*/}: Success: qrencode produced QR code for file \"$outfile1\" successfully. See \"$outfile4\"."
    fi
    # chmod 400 "$outfile3" "$outfile4" # using umask instead
    echo "${0##*/}: QR codes are in files \"$outfile3\" and \"$outfile4\""
  else
    echo "${0##*/}: File \"$outfile1\" is too big ($filesize > $MAX_FILESIZE_FOR_QR). Hence no QR codes will be produced."
  fi
  echo -e "Date: $(date)\nOpenSSL version: $(openssl version)\nPlaintext filename: $infile\nCiphertext file: $outfile1\ncommand 1: $command1\ncommand 2: $command2\ncommand 3: $command3\nFiles:\n$(ls -lG ${outfile}.*)" > "$outfile5"
  echo "${0##*/}: Metadata is in file \"$outfile5\"."
  echo "${0##*/}: SUCCESS! Look at ciphertext output in file \"$outfile1\"."
} # encryptSymmetricDouble()

# decryptSymmetricDouble()
# takes exactly 1 argument, a filename of a ciphertext
# takes 1 argument --> file name, decrypt file
decryptSymmetricDouble() {
  if [ "$#" -eq "0" ]; then # no argument given
    echo "${0##*/}: Error: argument missing in function decryptSymmetricDouble()"
    echo "${0##*/}: Take your QR code or your string and place it into a file first. Suggested file name: \"text.enc\"."
    echo "${0##*/}: Then decrypt the file."
    cleanup_exit 2
  fi
  infile="$1"
  if [ ! -f "$infile" ]; then
    echo "${0##*/}: ERROR: file \"$infile\" does not exist or is not a file. Aborting. "
    cleanup_exit 12
  fi
  case $(basename "$infile") in
  ?*.*)
    outfile="${infile%.*}" # remove the last extension, presumably .enc
    ;;
  *)
    outfile="$(dirname "$infile")/${PLAINNAME}" # no extension in filename
    echo "${0##*/}: WARNING: Input file \"$infile\" has no extension. It will be impossible to find corresponding hash file .sha. Expect a warning later."
    ;;
  esac
  echo "${0##*/}: Plaintext output file will be \"$outfile\"."
  if [ -e "$outfile" ]; then
    echo "${0##*/}: Error: $outfile already exists. Aborting."
    cleanup_exit 3
  fi
  # check if certain files DO exist
  read-passphrase-files-if-availble "decryption"

  # check hash
  infile2="${outfile}.$FILEEXTENSION_HASH" # existing original hash file from encryption
  if [ ! -f "$infile2" ]; then
    echo "${0##*/}: WARNING: Hash file $infile2 does not exist. Cannot do hash comparison. Skipping authentication. :( "
  else
    outfile2="${outfile}.$TMP.$FILEEXTENSION_HASH" # newly calculated hash file from ciphertext, used to compare with original hash
    openssl dgst -sha512 -out "$outfile2" "$infile"
    ret=$?
    if [ "$ret" -ne "0" ]; then
      echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not hash file \"$infile\"."
    else
      echo "${0##*/}: Success: openssl hashed file \"$infile\" successfully."
    fi
    difference=$(diff "$infile2" "$outfile2")
    if [ "$difference" != "" ]; then
      echo "${0##*/}: ERROR: sha512 hashes do not match: see files \"$infile2\" and \"$outfile2\". Aborting."
      cleanup_exit 4
    else
      echo "${0##*/}: Success: sha512 hashes do match. File is henceforth authenticated. See \"$infile2\"."
      cat "$infile2" "$outfile2"
      chmod 600 "$outfile2"
      rm "$outfile2"
    fi
  fi
  echo "${0##*/}: Be patient. Password hashing takes more than $HASHING_TIME_IN_SEC seconds each. So wait."
  # 1st decryption
  outfileT="${outfile}.$FILEEXTENSION_TMP"
  if [ -e "$outfileT" ]; then
    echo "${0##*/}: ERROR: file \"$outfileT\" does already exist. Will not overwrite. Aborting."
    cleanup_exit 5
  fi
  openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 $PASSPHRASE_FILE_AES_OPTION -base64 -in "$infile" -out "$outfileT" # yes, use -base64
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not decrypt file \"$infile\". Aborting."
    cleanup_exit 16
  else
    echo "${0##*/}: Success: openssl decrypted file \"$infile\" successfully."
  fi
  # 2nd decryption
  # outfile already set above
  openssl enc -d -chacha20 -salt -pbkdf2 -iter $SHA_HASH_ITERATIONS -md sha512 $PASSPHRASE_FILE_CHACHA_OPTION -in "$outfileT" -out "$outfile" # No -base64 here!
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: ERROR: openssl returned error \"$ret\". openssl could not decrypt file \"$outfileT\". Aborting."
    cleanup_exit 17
  else
    echo "${0##*/}: Success: openssl decrypted file \"$outfileT\" successfully."
  fi
  # chmod 400 "$outfile" # using umask instead
  echo "${0##*/}: Plaintext output in file \"$outfile\""
  # shred temp files
  chmod 600 "$outfileT"
  shred --iterations=$SHRED_ROUNDS --zero --remove "$outfileT"
  ret=$?
  if [ "$ret" -ne "0" ]; then
    echo "${0##*/}: Warning: shred returned error \"$ret\". shred could not shred file \"$outfileT\". Is \"shred\" installed? No problem, instead of shredding we will just remove it."
    rm "$outfileT"
  else
    echo "${0##*/}: Success: shred shredded temporary file \"$outfileT\" successfully."
  fi
  echo "${0##*/}: SUCCESS! Look at plaintext output in file \"$outfile\"."
} # decryptSymmetricDouble()

trap 'cleanup_exit' SIGINT

# this is an alternative to the `chmod 400 file` lines, but chmod seems to be simpler, fewer lines
# umask 0377  # https://en.wikipedia.org/wiki/Umask
# umask -S
# u=r,g=,o=
# umask_save=`umask` # preserve original state
# umask 0377
# ... create files (will be r--)
# umask "$umask_save" # return to previous state
umask "$UMASK_READONLY"

# openssl version
# on MacOS: LibreSSL ==> this version does not support "-" for stdin, nor -pbkdf2, nor -iter
# LibreSSL 2.8.3
# on Linux:
# OpenSSL 1.1.1g FIPS  21 Apr 2020
if [[ "$(openssl version)" =~ "ibre" ]]; then
  echo "${0##*/}: ===================================================================="
  echo "${0##*/}: WARNING: Detected that your version of OpenSSL is based on LibreSSL."
  echo "${0##*/}: WARNING: Detected version: $(openssl version)"
  echo "${0##*/}: WARNING: Results will not be cross-platform compatible."
  echo "${0##*/}: WARNING: LibreSSL has neither -pbkdf2 nor -iter options."
  echo "${0##*/}: WARNING: Will abort now to keep you out of trouble."
  echo "${0##*/}: ===================================================================="
  cleanup_exit 18
fi
# process arguments: look for --encrypt or --decrypt
operation="encrypt" # default
case "$1" in
--encrypt | --enc | --e | -encrypt | -enc | -e)
  operation="encrypt"
  shift # skip arg
  ;;
--decrypt | --dec | --d | -decrypt | -dec | -d)
  operation="decrypt"
  shift # skip arg
  ;;
esac

# process arguments: look for --help or --version
case "$1" in
--help | --hel | --he | --h | -help | -hel | -he | -h)
  usage
  exit 0 # no cleanup needed
  ;;     # success
--version | --versio | --versi | --vers | --ver | --ve | --v | -version | -versio | -versi | -vers | -ver | -ve | -v)
  usage
  exit 0 # no cleanup needed
  ;;     # success
esac

# give some guidance, summary
echo "${0##*/}: Install latest version of \"openssl\", \"shred\" and \"qrencode\"!"
echo "${0##*/}: It will NOT overwrite files. So, if you run it twice it will give error."
echo "${0##*/}: Remove old files manually first if you run script twice to encrypt."
echo "${0##*/}: Chosen operation is \"$operation\"."
echo -n "${0##*/}: Platform is: "
case "$OSTYPE" in
solaris*) echo "SOLARIS" ;;
darwin*) echo "OSX" ;;
linux*) echo "LINUX" ;;
bsd*) echo "BSD" ;;
msys*) echo "WINDOWS" ;;
*) echo "unknown: $OSTYPE" ;;
esac

# case of no arguments: stdin or error
if [ "$#" -lt "1" ]; then
  if [ "$operation" == "encrypt" ]; then
    echo "${0##*/}: No input file provided. Will read plaintext from stdin (keyboard)."
    encryptSymmetricDouble
    cleanup_exit 0
  else
    echo "${0##*/}: You must provide one or more files for decrypting. No file given as argument. Aborting."
    cleanup_exit 1
  fi
fi

# case of one or more arguments
FILESLASHSLASHUSED=0
for i in "$@"; do
  echo "${0##*/}: ===================================================================="
  # if this script is called from a Linux launcher the parameters passed via %U look like this:
  # example: file:///home/briefcase/foo.txt
  # If such name is found convert it: file:///home/briefcase/foo.txt --> /home/briefcase/foo.txt
  part1="$(echo $i | cut -c 1-7)"
  if [ "${part1}" == "file://" ]; then
    part2="$(echo $i | cut -c 8-)"
    i="$part2"
    # shellcheck disable=SC2034
    FILESLASHSLASHUSED=1
  fi
  # also file abc def.txt shows up as abc%20def.txt when called from a launcher
  # replace the "%20" with "\ "
  i="$(echo $i | sed 's/%20/\\ /g')"
  if [ "$operation" == "encrypt" ]; then
    encryptSymmetricDouble "$i"
  else
    decryptSymmetricDouble "$i"
  fi
done

# This code is just useful if script is kicked off via GUI such as file manager
# Not needed when used in terminal.
#if [ "${FILESLASHSLASHUSED}" -eq "1" ]; then
#  echo "${0##*/}: Done. Close window please by clicking X in top right window corner."
#else
#  echo -n "${0##*/}: Hit any key to continue ... "
#fi
#read YESNO

cleanup_exit 0 # success
# EOF
