#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
	#include <windows.h>

#endif

#define numberofmagics 800
#define maxlinelenght 256
#define MAX_PATH_LENGTH 4096



/* ─── ANSI Color Codes ─────────────────────────────────────────── */
#define RESET       "\x1b[0m"
#define BOLD        "\x1b[1m"
#define DIM         "\x1b[2m"

#define FG_WHITE    "\x1b[37m"
#define FG_CYAN     "\x1b[36m"
#define FG_BRED     "\x1b[91m"
#define FG_BGREEN   "\x1b[92m"
#define FG_BYELLOW  "\x1b[93m"
#define FG_BMAGENTA "\x1b[95m"
#define FG_BWHITE   "\x1b[97m"
/* ─── ANSI Color Codes ─────────────────────────────────────────── */

void cleaner(void);
void buffercleaner(void);
void print_banner(void);
bool checker(char*);
void lister(void);
bool extractor(const char*, FILE*);
//void enable_ansi(void);

typedef struct magicnum
{	

	char type[100];
	uint8_t magic_number[70];
	char extension[20];
	char threat_level[6];
	uint8_t size;
	uint8_t offset;

}magic_num;

uint8_t buffer[70];
magic_num *signatures = NULL;
int *count = NULL;





int main(void)
{	
	#ifdef _WIN32	    
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	    if (hOut == INVALID_HANDLE_VALUE) return 1;
	    DWORD dwMode = 0;
	    if (!GetConsoleMode(hOut, &dwMode)) return 1;
	    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	    SetConsoleOutputCP(CP_UTF8);

	#endif

	cleaner();

	const char *database_file = "magic_db.txt";
	FILE *database = fopen(database_file, "r");

	if(!extractor(database_file ,database))
	{	
		free(count);
		return 1;
	}


	while(1)
	{

		memset(buffer, 0, 70);
		char filename[MAX_PATH_LENGTH] = {0};
		char *extension = NULL;
		FILE *readfile = NULL;


		printf("[+] Enter the path of the file >>>> ");

		while(!readfile)
		{

			while(fgets(filename, MAX_PATH_LENGTH - 1, stdin) == NULL || strchr(filename, '\n') == NULL || (int)*filename == '\n')
			{

				if(strchr(filename, '\n') == NULL)
				{
					buffercleaner();
				}

				if((int)*filename == '\n')
				{
					printf("[-] Please enter a valid filename OR valid command >>>> ");
				}
			
			}

			if(strcmp(filename, "exit\n") == 0) 
			{	
				free(signatures);
				free(count);
				exit(0);
			}

			else if(strcmp(filename, "list\n") == 0)
			{
				lister();
				printf("[+] Enter the path of the file >>>> ");
			}

			else if(strcmp(filename, "clear\n") == 0)
			{
				cleaner();

				printf("[+] Enter the path of the file >>>> ");
			}	

			else if(strcmp(filename, "help\n") == 0 || strcmp(filename, "-h\n") == 0 || strcmp(filename, "HELP\n") == 0 || strcmp(filename, "-H\n") == 0)
			{
				printf("\n\nlist : to list all files on current directory\nexit : to exit the program\nhelp : to show this help messege\nclear : clean the shell\n");
				printf("Also please note that plain text files such as, source codes, scripts dont have magic numbers. So they cant ba detect by my simple programm.\n\n");

				printf("[+] Enter the path of the file >>>> ");
			}

			else
			{

				filename[strcspn(filename, "\n")] = 0;
				readfile = fopen(filename, "rb");

				if(!readfile)
				{
					printf("[-] Please enter a valid filename >>>> ");
				}

			}

		}
		
		fread(buffer, 1, 69, readfile);
		extension = strrchr(filename, '.');

		bool found = checker(extension);
		fclose(readfile);
		
		if(!found)
		{
			printf("\n✗ Unknown file type\n");
			printf("  First 65 bytes (hex): ");

			for(register int i = 0 ; i < 65 ; i++)
			{
				printf("%02X ", buffer[i]);
			}

			printf("\n");

		}

		printf("\nPress Enter to check another file...");
		buffercleaner();

	}

	free(signatures);
	free(count);
	return 0;

}





bool extractor(const char *database_file, FILE *database)
{

	if(!database)
		{
			fprintf(stderr, "[-] Error while opening the databse file : %s\n", database_file);
			return false;
		}

	signatures = malloc(numberofmagics * sizeof(magic_num));

	if(!signatures)
		{
			fprintf(stderr, "[-] Error while allocating space for the magic number list\n");
			return false;
		}

	char line[maxlinelenght];
	count = calloc(1, sizeof(int));


	while(fgets(line, sizeof(line), database) && *count < numberofmagics)
	{

		if(line[0] == '#' || line[0] == '\n' || line[0] == '\r')
			continue;

		line[strcspn(line, "\n")] = 0;
		char type[100], extension[20], threat_level[6], offset[5], hex_str[128];

		char *token = strtok(line, "|");
		if(!token) continue;
		strncpy(type, token, sizeof(type) - 1);
		type[sizeof(type) - 1] = '\0';

		token = strtok(NULL, "|");
		if(!token) continue;
		strncpy(extension, token, sizeof(extension) - 1);
		extension[sizeof(extension) - 1] = '\0';

		token = strtok(NULL, "|");
		if(!token) continue;
		strncpy(threat_level, token, sizeof(threat_level) - 1);
		threat_level[sizeof(threat_level) - 1] = '\0';

		token = strtok(NULL, "|");
		if(!token) continue;
		strncpy(offset, token, sizeof(offset) - 1);
		offset[sizeof(offset) - 1] = '\0';		

		token = strtok(NULL, "|");
		if(!token) continue;
		strncpy(hex_str, token, sizeof(hex_str) - 1);
		hex_str[sizeof(hex_str) - 1] = '\0';

		memset(&signatures[*count], 0, sizeof(magic_num));
        strncpy(signatures[*count].type, type, sizeof(signatures[*count].type) - 1);
        strncpy(signatures[*count].extension, extension, sizeof(signatures[*count].extension) - 1);
        strncpy(signatures[*count].threat_level, threat_level, sizeof(signatures[*count].threat_level) - 1);
        signatures[*count].offset = atoi(offset);


        uint8_t byte_count = 0;
        char *byte_tok = strtok(hex_str, " ");

        while (byte_tok && byte_count < 69) 
        {
            signatures[*count].magic_number[byte_count++] = (uint8_t)strtol(byte_tok, NULL, 16);
            byte_tok = strtok(NULL, " ");
        }

        signatures[*count].size = byte_count;

        if (byte_count == 0) continue;
        (*count)++;

	}

    fclose(database);
    printf("===========================================================\n");
    printf("[+] Loaded %d signatures from %s\n", *count, database_file);
    printf("===========================================================\n\n\n");
    return *count > 0;
}





bool checker(char *extension_ptr)
{	

	if(extension_ptr == NULL)
    {
    	printf("[-] File extension is NULL");
	}

	for(register int i = 0 ; i < *count ; i++)
	{
        if(memcmp(buffer + signatures[i].offset, signatures[i].magic_number, signatures[i].size) == 0)
        {	

            printf("\n[✓] File type detected: %s\n", signatures[i].type);

            if(extension_ptr == NULL)
		    {
		    	printf("[-] File extension is NULL, could be attack, could be misconfiguration");
			}

			else
			{	

	            if(strcmp(extension_ptr + 1, signatures[i].extension) == 0)
	            {
	            	printf("[+] File extension is matching with the magic number\n");
	            }

	            else
	            {	

	            	bool final_checker = false;

		            for(register int j = 0 ; j < *count ; j++)
		            {
		            	if((memcmp(buffer + signatures[j].offset, signatures[j].magic_number, signatures[j].size) == 0) && (strcmp(extension_ptr + 1, signatures[j].extension) == 0))
		            	{

		            		printf("[+] File extension is matching with the magic number\n");
		            		final_checker = true;
		            		break;

		            	}
		            }

		            if(!final_checker)
		            {
			            printf("[-] DANGER !!!!! File extension is not matching with the magic number. Take a action against the file\n");
			            printf("[*] Threat level: %s\n", signatures[i].threat_level);
		            }

	        	}

	        }
      
            return true;
        }
	}

	return false;
}





void cleaner(void)
{
	#ifdef _WIN32
		system("cls");
	#else
		system("clear");
	#endif

	print_banner();
	printf("\n");
}





void lister(void)
{

	printf("\n\n================================================================FILES ON CURRENT DIRECTORY================================================================\n\n");

	#ifdef _WIN32
		system("dir");
	#else
		system("ls -l");
	#endif

	printf("\n==========================================================================================================================================================\n\n\n");
}



// NOTE :- The banner is developed with help of claude AI

void print_banner() {
    printf("\n");
    printf(FG_CYAN "  ╔═══════════════════════════════════════════════════════════════╗\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_BMAGENTA BOLD
    "  ║  ███╗   ███╗ █████╗  ██████╗ ██╗ ██████╗                      ║\n"
    "  ║  ████╗ ████║██╔══██╗██╔════╝ ██║██╔════╝                      ║\n"
    "  ║  ██╔████╔██║███████║██║  ███╗██║██║                           ║\n"
    "  ║  ██║╚██╔╝██║██╔══██║██║   ██║██║██║                           ║\n"
    "  ║  ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║╚██████╗                      ║\n"
    "  ║  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝                      ║\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_BYELLOW BOLD
    "  ║  ███████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗███████╗██╗    ║\n"
    "  ║  ██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║    ║\n"
    "  ║  ███████╗█████╗  ██╔██╗██║   ██║   ██║██╔██╗██║█████╗  ██║    ║\n"
    "  ║  ╚════██║██╔══╝  ██║╚████║   ██║   ██║██║╚████║██╔══╝  ██║    ║\n"
    "  ║  ███████║███████╗██║ ╚███║   ██║   ██║██║ ╚███║███████╗███████║\n"
    "  ║  ╚══════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝╚══════╝╚═════╝║\n" RESET);
    printf(FG_CYAN "  ║                                                               ║\n" RESET);
    printf(FG_CYAN "  ║  " RESET FG_BGREEN "  File Signature & Magic Number Detector                    " RESET FG_CYAN " ║\n" RESET);
    printf(FG_CYAN "  ║  " RESET DIM FG_WHITE "  By Piyumila Perera  |  System Security Analysis  |  v1.0.0 " RESET FG_CYAN "║\n" RESET);
    printf(FG_CYAN "  ╚═══════════════════════════════════════════════════════════════╝\n" RESET);
    printf("\n");
    printf(FG_BWHITE BOLD "  Usage:\n" RESET);
    printf(FG_BGREEN "  ❯ " RESET "Enter a file path to analyze its magic number and detect spoofing.\n");
    printf(FG_BGREEN "  ❯ " RESET FG_BYELLOW "{list}" RESET " — List all files in the current directory.\n");
    printf(FG_BGREEN "  ❯ " RESET FG_BRED "{exit}" RESET " — Exit the program.\n");
    printf("\n");
    printf(FG_CYAN DIM "  ⓘ  Note: Plain text files (source code, scripts) have no magic\n" RESET);
    printf(FG_CYAN DIM "     numbers and cannot be detected by this tool.\n" RESET);
    printf("\n");
}





/*void enable_ansi() 
{

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);

}*/





void buffercleaner(void)
{	
	int x;
	while((x = getchar()) !=  '\n' && x != EOF);
}