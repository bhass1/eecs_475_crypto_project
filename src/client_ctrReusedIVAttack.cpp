#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <cstring>

using namespace std;

//for right now, only works with messages of same length
//TODO: make work for different length messages to recover shorter message

const int dictSize = 354983;
int xoredSize;
const int MAXCIPHERBUFFER = 100;

string printCharVec (vector<char>& vec) {
	string output = "";

	for(int i=0;i<vec.size();++i)
		output += vec[i];

	return output;
}

bool isInDictFull (string& candidate, set<string>& dict) {
	if(dict.find(candidate) == dict.end())
		return false;
	else
		return true;
}

bool isInDictPartial (string candidate, vector<string>& dict, bool back) {
	bool matchingFirstLetterOnce = false;

	if (back) reverse(candidate.begin(), candidate.end());

	//use binary search to find the first term with the starting letter
	int start = lower_bound(dict.begin(), dict.end(), candidate) - dict.begin();
	//cout << "start: " << dict[start] << " (" << start << ") for " << candidate << " in a " << (back?"back":"front") << endl;

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

	cout << "didn't find it" << endl;

	//if we get here we've checked the whole dictionary and
	//nothing is prefixed/postfixed by our candidate
	return false;
}

bool isInDictSubstr(const string& candidate, vector<string>& dict) {
	for (int i = 0; i < dictSize; ++i) {
		if (candidate.length() > dict[i].length())
			continue;
		cout << "considering: " << dict[i] << endl;
		for (int j = 0; j <= (dict[i].length() - candidate.length()); ++j) {
			if (dict[i][j] == candidate[0]) {
				cout << "  comparing: " << dict[i].substr(j, candidate.length()).length() << endl;
				//compare candidate to substring of dictionary
				if (!strcmp(candidate.c_str(), dict[i].substr(j, candidate.length()).c_str()))
					return true;
			}
		}
	}

	return false;
}

bool isPotential (char* str, bool isAtFront, bool isAtBack, set<string>& dict, vector<string>& frontDict, vector<string>& backDict) {
	vector<string> words;
	string word = "";
	bool checkFirstFull = true, checkLastFull = true;
	
	//initial check to make sure there are no control characters
	//and that it lies in ascii land i.e. most significant bit is 1
	for (int i = 0; i < strlen(str); ++i) {
		if (iscntrl(str[i]) || str[i] > 0x7F || str[i] < 0x00) {
			cout << "nonreadable character" << endl;
			return false;
		}
	}

	//cout << "here" << endl;

	//delimit
	for (int i=0;i<strlen(str);++i) {
		//cout << "for char: |" << str[i] << "|\n";

		//special case for apostrophe
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
			cout << "failed on <letter><digit/punct><letter>" << endl;
			return false;
		}

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
			//cout << " is alpha and word now equals: " << word << endl;
		}
		//if we reach the end of the parameter and still have a word to add
		if (i == strlen(str) - 1 && word.length() > 0) {
			words.push_back(word);
		}
	}

	for (int i = 0; i < words.size(); ++i) {
		cout << "|" << words[i] << "|\n";
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
    		cout << "full word " << words[i] << " failed" << endl;
    		return false;
    	}
    }

    //back end of word compare of dictionary
    if(!checkFirstFull)
    	//if there is only one word, we must check it for being a prefix and post fix
		if(!isInDictPartial(words[0], backDict, true) && words.size() != 1) {
			cout << "first partial word failed" << endl;
			return false;
		}

	//front end of word compare of dictionary
	if(!checkLastFull)
		//if there is only one word, we must check it for being a prefix and post fix
		if(!isInDictPartial(words[words.size() - 1], frontDict, false) && words.size() != 1) {
			cout << "last partial word failed" << endl;
			return false;
		}

	if (words.size() == 1) {
		//we need to see if the word could be in the middle of any dictionary entry
		if (!isInDictSubstr(words[0], frontDict)) {
			cout << "dictionary term substring failed" << endl;
			return false;
		}
	}

	return true;
}

vector<int> tryGuess (const string& str, vector<char>& xored, set<string>& dict, vector<string>& frontDict, vector<string>& backDict) {
	char* potential[MAXCIPHERBUFFER];
	vector<int> validPositions;
	for (int i = 0; i < xoredSize - str.length() + 1; ++i) {
		for (int j = 0; j < str.length(); ++j) {
			potential[j] = str[j] ^ xored[i + j];
		}
		if (isPotential(potential, i == 0, i == xoredSize - str.length() + 1), dict, frontDict, backDict) {
			validPositions.push_back(i);
			cout << "at pos: " << i << " \'";
			for (int k = 0; k < str.length(); ++k)
				cout << potential[k];
			cout << endl;
		}
	}

	return validPositions;
}

/*
void constructGuess (vector<char>& xored, set<string>& dict, vector<string>& frontDict, vector<string>& backDict) {

}
*/

int main(int argc, char* argv[]) {
	ifstream finDict("words.txt");

	
	ifstream fin1("cipher1.txt");
	ifstream fin2("cipher2.txt");

	char from1, from2;
	vector<char> msgsXored;
	set<string> dict;

	
	while(fin1 >> from1 && fin2 >> from2) {
		msgsXored.push_back((char) ((int)from1 ^ (int)from2));
	}


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

	//test isPotential
	/*
	char test[100] = "estidigi";
	cout << test << endl;
	cout << isPotential(test, 0, 0, dict, frontDict, backDict) << endl;
	*/

	//Begin guessing
	/*
	ifstream fin3("commonwords.txt");

	string temp;
	vector<string> guesses;
	vector<char> messageMate;

	
	while(fin3 >> temp) guesses.push_back(temp);

	for(int i=0;i<guesses.size();++i) {
		//try word from common
		guesses[i];
		messageMate.clear();

		//get what other message would be with guess
		for(int j=0;j<guesses[i].length();++i) {
			messageMate.push_back(guesses[i][j] ^ msgsXored[j]);
		}

		//print
		cout << guesses[i] << endl;
		cout << printCharVec(messageMate) << endl;

		//evaluate likelihood of message mate
		
	}
	*/
	string guess;

	for (int i = 0; i < 100; ++i) {
		cout << "Guess: "
		cin >> guess;

		vector<int> locations = tryGuess(guess, msgsXored, dict, frontDict, backDict);
	}


}