#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <cstring>
#include <sstream>

using namespace std;

//for right now, only works with messages of same length
//TODO: make work for different length messages to recover shorter message

const int dictSize = 354983;
int xoredSize;
const int MAXCIPHERBUFFER = 100;

//receives a string and a dictionary
//returns true if the candidate is a dictionary term
//
bool isInDictFull (const string& candidate, const set<string>& dict) {
	if(dict.find(candidate) == dict.end())
		return false;
	else
		return true;
}

//receives a string and dictionary vector
//if back is true, returns true if candidate is at the end of any dictionary term
//if back is false, returns true if candidate is at the beginning of any dictionary term
//
bool isInDictPartial (string candidate, const vector<string>& dict, bool back) {
	bool matchingFirstLetterOnce = false;

	if (back) reverse(candidate.begin(), candidate.end());

	//use binary search to find the first term with the starting letter
	int start = lower_bound(dict.begin(), dict.end(), candidate) - dict.begin();

	for (int i = start; i < dictSize; ++i) {
		if(candidate[0] != dict[i][0]) {
			if (matchingFirstLetterOnce)
				break;
			continue;
		}

		//if we make it this far, we've found a term with a matching first letter
		matchingFirstLetterOnce = true;

		if(candidate.length() > dict[i].length())
			continue;

		if(!strcmp(candidate.c_str(), dict[i].substr(0, candidate.length()).c_str()))
			return true;
	}

	//cout << "didn't find it" << endl;

	//if we get here we've checked the whole dictionary and
	//nothing is prefixed xor postfixed by our candidate
	return false;
}

//receives a string and a dictionary vector
//returns true if the dictionary contains a word that contains the
//candidate substring
//
bool isInDictSubstr(const string& candidate, const vector<string>& dict) {
	for (int i = 0; i < dictSize; ++i) {
		if (candidate.length() > dict[i].length())
			continue;
		for (int j = 0; j <= (dict[i].length() - candidate.length()); ++j) {
			if (dict[i][j] == candidate[0]) {
				//compare candidate to substring of dictionary
				if (!strcmp(candidate.c_str(), dict[i].substr(j, candidate.length()).c_str()))
					return true;
			}
		}
	}

	return false;
}

//receives a string and a dictionary represented as 3 containers for the purposes of speed
//returns true if:
//		the string contains only words that exist in the dictionary
//		the string contains no illegal punctuation patterns
//		the string contains only printable ascii characters
//if a word is truncated by being at the beginning or end of the guess, 
//a search is made of the dictionary for this truncation being the beginning
//or end of a dictionary term
//
bool isPotential (char* str, bool isAtFront, bool isAtBack, const set<string>& dict, const vector<string>& frontDict, const vector<string>& backDict) {
	vector<string> words;
	string word = "";
	bool checkFirstFull = true, checkLastFull = true;
	
	//initial check to make sure there are no control characters
	//and that it lies in ascii land i.e. most significant bit is 1
	for (int i = 0; i < strlen(str); ++i) {
		if (iscntrl(str[i]) || str[i] > 0x7F || str[i] < 0x00) {
			//cout << "nonreadable character" << endl;
			return false;
		}
	}

	//delimit
	for (int i=0;i<strlen(str);++i) {
		//special case for apostrophe i.e. contractions
		if (str[i] == '\'') {
			//if we have a word going in, split here and add it
			if (word.length() > 0) {
				words.push_back(word);
				word = "";
			}
			
			//if the \' is not the last character
			if (i != strlen(str) - 1) {
				//if it is followed by a letter
				if (isalpha(str[i+1])) {
					word += str[i];
				}
			}

			continue;
		}

		//fail on <letter><X><letter> when <X> is a digit or punctuation
		if (i != 0 && i != strlen(str) - 1 
			&& (ispunct(str[i]) || isdigit(str[i]))
			&& isalpha(str[i-1]) && isalpha(str[i+1])) {
			//cout << "failed on <letter><digit/punct><letter>" << endl;
			return false;
		}

		//fail on <X><X> when <X> is punctuation
		/*
		if (i != strlen(str) - 1
			&& ispunct(str[i])
			&& ispunct(str[i+1])) {
			//cout << "failed on double punctuation" << endl;
			return false;
		}
		*/

		//delimit by whitespace and punctuation
		if (iswspace(str[i]) || ispunct(str[i]) || isdigit(str[i])) {
			if (word.length() > 0) {
				words.push_back(word);
				word = "";
			}
		}
		else {
			//if capital letter
			if (isupper(str[i]))
				//give a lowercase version to the dictionary check
				word += (char)(str[i] + 0x20);
			else
				word += str[i];
		}
		//if we reach the end of the parameter and still have a word to add
		if (i == strlen(str) - 1 && word.length() > 0) {
			words.push_back(word);
		}
	}

	//no alphanumeric chars
	if (words.size() == 0) {
		return 0;
	}

	//if first char in parameter is a letter
	if (str[0] == words[0][0]  && !isAtFront) {
		//we have character(s) at the front but
		//we're not at the beginning of the message
		//so treat the word as back end of partial

		checkFirstFull = false;
	}

	//if last char in param is a letter
	if (str[strlen(str) - 1] == words[words.size() - 1][words[words.size() - 1].size() - 1] && !isAtBack) {
		//we have character(s) at the back but
		//we're not at the end of the message
		//so we treat the word as front end of potential

		checkLastFull = false;
	}

    //loops through complete words
    int startIndex = (checkFirstFull?0:1);
    int endIndex = (checkLastFull?words.size():(words.size() - 1));
    for (int i = startIndex; i < endIndex; ++i) {
    	if (!isInDictFull(words[i], dict)) {
    		//cout << "full word " << words[i] << " failed" << endl;
    		return false;
    	}
    }

    //back end of word compare of dictionary
    if(!checkFirstFull)
    	//if there is only one word, we must check it for being a prefix and post fix
		if(!isInDictPartial(words[0], backDict, true) && words.size() != 1) {
			//cout << "first partial word failed" << endl;
			return false;
		}

	//front end of word compare of dictionary
	if(!checkLastFull)
		//if there is only one word, we must check it for being a prefix and post fix
		if(!isInDictPartial(words[words.size() - 1], frontDict, false) && words.size() != 1) {
			//cout << "last partial word failed" << endl;
			return false;
		}

	if (words.size() == 1) {
		//we need to see if the word could be in the middle of any dictionary entry
		if (!isInDictSubstr(words[0], frontDict)) {
			//cout << "dictionary term substring failed" << endl;
			return false;
		}
	}

	return true;
}

//receives a guess string and a char vector of xored characters
//prints to stdout guess hits and their locations
//
//MODIFIES: stdout
//
void tryGuess (const string& str, const vector<char>& xored, const set<string>& dict, const vector<string>& frontDict, const vector<string>& backDict) {
	char potential[MAXCIPHERBUFFER];
	vector<int> validPositions;

	cout << "i from 0 to " << (xoredSize - str.length() + 1) << endl;

	for (int i = 0; i < xoredSize - str.length() + 1; ++i) {
		int j;
		for (j = 0; j < str.length(); ++j) {
			potential[j] = (char) (str[j] ^ xored[i + j]);
		}
		//c string needs to end with null terminator
		potential[j] = (char) 0x00;

		if (isPotential(potential, i == 0, i == xoredSize - str.length() + 1, dict, frontDict, backDict)) {
			validPositions.push_back(i);
			cout << "at pos: " << i << " \'";
			for (int k = 0; k < str.length(); ++k)
				cout << potential[k];
			cout << "\'" << endl;
		}
	}
}

int main(int argc, char* argv[]) {
	//usage
	if (argc < 3) {
		cout << "error: usage: <file1> <file2>" << endl;
		return 0;
	}

	//input
	ifstream finDict("words.txt");

//	if (!finDict.open()) {
//		cout << "error: dictionary file \'words.txt\' not found" << endl;
//		return 0;
//	}

	ifstream fin1(argv[1]);
	ifstream fin2(argv[2]);

	vector<char> msgsXored;
	set<string> dict;

	stringstream buffer, buffer2;
	char cipher1[MAXCIPHERBUFFER];
	char cipher2[MAXCIPHERBUFFER];
	buffer << fin1.rdbuf();
	buffer2 << fin2.rdbuf();

	strcpy(cipher1, buffer.str().c_str());
	strcpy(cipher2, buffer2.str().c_str());

	for (int i = 0; i < strlen(cipher1); ++i)
		msgsXored.push_back(cipher1[i] ^ cipher2[i]);

	//test print
	/*
	for (int i = 0; i < strlen(cipher1); ++i) {
		cout << i << " " << (int) cipher1[i] << " " << (int) cipher2[i] << " " << (int) msgsXored[i] << endl;
	}
	cout << endl;
	*/

	//set global
	xoredSize = msgsXored.size();

	//read in dictionary
	string dictEntry;
	while (finDict >> dictEntry) {
		dict.insert(dictEntry);
	}

	vector<string> frontDict(dict.begin(), dict.end());
	vector<string> backDict;

	//creates a dictionary that is back alphabetized
	string temp;
	for (int i = 0; i < frontDict.size(); ++i) {
		temp = frontDict[i];
		reverse(temp.begin(), temp.end());
		backDict.push_back(temp);
	}
	sort(backDict.begin(), backDict.end());

	//Begin guessing, arbitrarily 100 guesses
	string guess;

	for (int i = 0; i < 100; ++i) {
		cout << "Guess:     ";
		getline(cin, guess);

		tryGuess(guess, msgsXored, dict, frontDict, backDict);
	}

	return 0;
}
