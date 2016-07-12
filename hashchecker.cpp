#include "key.h"
#include "crypter.h"

using namespace std;

void swap(SecureString &s, int i, int j)
{
  char temp = s[i];
  s[i] = s[j];
  s[j] = temp;
}
void permutation(int k, SecureString &s)
{
  for(unsigned int j = 1; j < s.size(); ++j)
    {
      swap(s, k % (j + 1), j);
      k = k / (j + 1);
    }
}
int GetDigitValue (char digit)
{
  int asciiOffset, digitValue;
  if (digit >= 48 && digit <= 57)
    {
      // code for '0' through '9'
      asciiOffset = 48;
      digitValue = digit - asciiOffset;
      return digitValue;
    }
  else if (digit >= 65 && digit <= 70)
    {
      // digit is 'A' through 'F'
      asciiOffset = 55;
      digitValue = digit - asciiOffset;
      return digitValue;
    }
  else if (digit >= 97 && digit <= 102)
    {
      // code for 'a' through 'f'
      asciiOffset = 87;
      digitValue = digit - asciiOffset;
      return digitValue;
    }
  else
    {
      // illegal digit
      return -1;
    }
}
vector<unsigned char> Convert (SecureString hexNumber)
// assumes 2 character string with legal hex digits
{
  vector<unsigned char> chars;
  int size = hexNumber.length();
  for (int i = 0; i < size; i+=2)
    {
      char highOrderDig = hexNumber[i];
      char lowOrderDig  = hexNumber[i+1];
      int lowOrderValue = GetDigitValue(lowOrderDig);//;  convert lowOrderDig to number from 0 to 15
      int highOrderValue = GetDigitValue(highOrderDig);//; convert highOrderDig to number from 0 to 15
      chars.push_back(lowOrderValue + 16 * highOrderValue);
    }
  return chars;
}
inline double Factorial(int x) {
  return (x == 1 ? x : x * Factorial(x - 1));
}
int main(int argc, char* argv[])
{
  if (argc != 7){
    printf("Hashchecker needs to know the cryptographic details of your wallet!\nUsage: hashchecker pw_to_permute iterations salt crypted_key public_key crypted_secret\n");
    return 1;
  }
  CCrypter crypter;
  CKeyingMaterial vMasterKey;

  // Try any password as input
  SecureString attempt = argv[1];

  const unsigned int nDeriveIterations = atoi(argv[2]);//29731;
  const vector<unsigned char> chSalt = Convert(argv[3]);//"b29a2e128e8e0a2f");//argv[1];
  const vector<unsigned char> vchCryptedKey = Convert(argv[4]);//"982a07407ccb8d70514e7b7ccae4b53d68318ec41fd2bf99bf9dbcafd2f150a92c6eb8f9ea743b782fc5b85403421c1d");//argv[2];
  const vector<unsigned char> vchPubKey = Convert(argv[5]);//"03fefd771544971f3ab95b041bbce02cc799a335d0d12c3bcd46c7c61a4e3ba897");
  const vector<unsigned char> vchCryptedSecret = Convert(argv[6]);//"17169083a74b07ff3497027af7423b9aec1593c90f15a57f52c368593947c85e37b03430840ad48ef409e97ba5a4cdeb");

  double count = Factorial(attempt.size());
  bool found = false;

  for (int i = 0; i <= count; i++)
    {
      if (i > 0) {//test the word as typed in on first iteration
        permutation(i-1, attempt);
      }

      const SecureString strWalletPassphrase = attempt;
      cout << i << "-" << strWalletPassphrase <<"\n";
      if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, chSalt, nDeriveIterations, 0))
        {
          cout << i << " " << strWalletPassphrase <<"\n";
          continue;
        }
      if (!crypter.Decrypt(vchCryptedKey, vMasterKey))
        {
          cout << i << " " << strWalletPassphrase <<"\n";
          continue;
        }

      CSecret vchSecret;
      if(!DecryptSecret(vMasterKey, vchCryptedSecret, Hash(vchPubKey.begin(), vchPubKey.end()), vchSecret))
        {
          cout << "** didn't decrypt **" <<"\n";
          continue;
        }
      if (vchSecret.size() != 32)
        {
          cout << "** wrong size secret **" <<"\n";
          continue;
        }
      CKey key;
      key.SetPubKey(vchPubKey);
      key.SetSecret(vchSecret);
      if (key.GetPubKey() == vchPubKey)
        {
          cout<<"Found one: "<<strWalletPassphrase<<"\n";
          found = true;
          break;
        }
      // else
      //     cout << "** didn't get the pubkey back **\n";
    }
  if (found)
    cout << "Found it! Congratulations\n";
  return 0;
}
