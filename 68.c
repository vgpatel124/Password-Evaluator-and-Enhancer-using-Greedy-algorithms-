#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#define MIN_LENGTH 8
#define MAX_LENGTH 20

// Global variables
int hasLower = 0;
int hasUpper = 0;
int hasDigit = 0;
int hasSpecial = 0;

// Function prototypes
int isDigit(char c);
int isSpecial(char c);
void countCharTypes(const char *password);
int containsDictionaryWord(const char *password);
void breakSequences(char *password);
void addMissingCharacterTypes(char *password, int *len);
int makeGreedyImprovements(char *password);
int calculateStrengthPercentage(const char *password);
int provideWeakPasswordSuggestions(char *password);
void generateStrongPasswordSuggestion(int length);
void displayPasswordStatistics(const char *password);
void displayMenu();

// Check if a charcter is a Digit
int isDigit(char c)
{
    return (c >= '0' && c <= '9');
}

// Check is a character is a special character
int isSpecial(char c)
{
    return (strchr("!@#$%^&*()-+[]{}|;:,.<>?/", c) != NULL);
}

// Count types of character in password
void countCharTypes(const char *password)
{
    hasDigit = hasLower = hasSpecial = hasUpper = 0;
    while (*password)
    {
        if (islower(*password))
            hasLower = 1;
        if (isupper(*password))
            hasUpper = 1;
        if (isDigit(*password))
            hasDigit = 1;
        if (isSpecial(*password))
            hasSpecial = 1;
        password++;
    }
}

// Check if a password contains any common dictionary words
int containsDictionaryWord(const char *password)
{
    const char *commonWords[] = {"password", "123456", "qwerty", "abc123", "letmein", "welcome", "admin", "password1"};
    int i;
    for (i = 0; i < sizeof(commonWords) / sizeof(commonWords[0]); i++)
    {
        if (strstr(password, commonWords[i]) != NULL)
        {
            return 1;
        }
    }
    return 0;
}

// Break sequence of repeated characters
void breakSequences(char *password)
{
    int len = strlen(password), i;
    for (i = 2; i < len; i++)
    {
        if (password[i] == password[i - 1] && password[i] == password[i - 2])
        {
            if (password[i] == 'z')
                password[i] = 'a';
            else if (password[i] == 'Z')
                password[i] = 'A';
            else
                password[i]++;
        }
    }
}

int makeGreedyImprovements(char *password)
{
    countCharTypes(password);

    int len = strlen(password);
    if (len >= MAX_LENGTH - 4)
        return -1;

    // Add missing character types if needed
    if (!hasLower && len < MAX_LENGTH - 1)
        password[len++] = 'a';
    if (!hasUpper && len < MAX_LENGTH - 1)
        password[len++] = 'A';
    if (!hasDigit && len < MAX_LENGTH - 1)
        password[len++] = '1';
    if (!hasSpecial && len < MAX_LENGTH - 1)
        password[len++] = '!';
    password[len] = '\0';

    // Break common patterns
    const char *patterns[] = {"123", "abc", "qwerty"};
    int i, j;
    for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    {
        char *pos = strstr(password, patterns[i]);
        while (pos)
        {
            for (j = 0; j < strlen(patterns[i]); j++)
            {
                if (pos[j] == 'z')
                    pos[j] = 'a';
                else if (pos[j] == 'Z')
                    pos[j] = 'A';
                else
                    pos[j]++;
            }
            pos = strstr(pos, patterns[i]); // Find the next occurrence
        }
    }

    // Break sequences introduced by greedy improvements
    breakSequences(password);
    printf("\n====================================================");
    printf("\nPassword after making greedy changes: %s\n", password);
    printf("====================================================");

    char response[10];
    printf("Do you want to keep this password? (yes/no): ");
    scanf("%9s", response);
    printf("====================================================");

    if (strcasecmp(response, "yes") == 0)
        return 1;
    else
        return 0;
}

// Calculate the strength of the password
int calculateStrengthPercentage(const char *password)
{
    int length = strlen(password);
    int lengthScore = 0;
    int typeScore = 0;
    int penaltyScore = 0;

    if (length < MIN_LENGTH || length > MAX_LENGTH)
        return -1;

    countCharTypes(password);

    if (length >= MAX_LENGTH)
        lengthScore = 30;
    else if (length >= 16)
        lengthScore = 25;
    else if (length >= 12)
        lengthScore = 20;
    else if (length >= MIN_LENGTH)
        lengthScore = 10;

    typeScore += (hasLower ? 10 : 0);
    typeScore += (hasUpper ? 10 : 0);
    typeScore += (hasDigit ? 15 : 0);
    typeScore += (hasSpecial ? 15 : 0);

    if (hasLower && hasUpper && hasDigit && hasSpecial)
        typeScore += 15;

    if (containsDictionaryWord(password))
        penaltyScore += 30;

    char *tempPassword = strdup(password);
    if (tempPassword == NULL)
    {
        printf("Memory allocation failed.\n");
        return -1;
    }

    breakSequences(tempPassword);
    free(tempPassword);

    if (strstr(password, "123") || strstr(password, "abc") || strstr(password, "qwerty"))
        penaltyScore += 20;

    int totalScore = lengthScore + typeScore - penaltyScore;
    if (totalScore < 0)
        totalScore = 0;
    if (totalScore > 100)
        totalScore = 100;

    return totalScore;
}

int provideWeakPasswordSuggestions(char *password)
{
    printf("\n\n=========== Suggestions to strengthen your password =========== \n");
    countCharTypes(password);
    if (strlen(password) < MIN_LENGTH)
        printf("- Increase length to at least %d characters.\n", MIN_LENGTH);
    if (!hasLower)
        printf("- Add lowercase letters.\n");
    if (!hasUpper)
        printf("- Add uppercase letters.\n");
    if (!hasDigit)
        printf("- Add digits.\n");
    if (!hasSpecial)
        printf("- Add special characters (e.g., !@#$%^&*).\n");
    if (containsDictionaryWord(password))
        printf("- Avoid using common dictionary words.\n");
    if (strstr(password, "123") || strstr(password, "abc") || strstr(password, "qwerty"))
        printf("- Avoid common patterns like '123', 'abc', or 'qwerty'.\n");
    printf("=============================================================== \n");

    int res = makeGreedyImprovements(password);
    return res;
}

// Generate a strong password suggestion
void generateStrongPasswordSuggestion(int length)
{
    if (length < MIN_LENGTH || length > MAX_LENGTH)
    {
        printf("Length must be between %d and %d characters.\n", MIN_LENGTH, MAX_LENGTH);
        return;
    }
    char password[length + 1];
    const char lower[] = "abcdefghijklmnopqrstuvwxyz";
    const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char digits[] = "0123456789";
    const char specials[] = "!@#$%^&*()-+[]{}|;:,.<>?/";
    static int seeded = 0;
    if (!seeded)
    {
        srand(time(NULL));
        seeded = 1;
    }

    password[0] = lower[rand() % (sizeof(lower) - 1)];
    password[1] = upper[rand() % (sizeof(upper) - 1)];
    password[2] = digits[rand() % (sizeof(digits) - 1)];
    password[3] = specials[rand() % (sizeof(specials) - 1)];
    int i;
    for (i = 4; i < length; i++)
    {
        int type = rand() % 4;
        switch (type)
        {
        case 0:
            password[i] = lower[rand() % (sizeof(lower) - 1)];
            break;
        case 1:
            password[i] = upper[rand() % (sizeof(upper) - 1)];
            break;
        case 2:
            password[i] = digits[rand() % (sizeof(digits) - 1)];
            break;
        case 3:
            password[i] = specials[rand() % (sizeof(specials) - 1)];
            break;
        }
    }
    password[length] = '\0';
    printf("\n===================================================================\n");
    printf("Example of a strong password with length %d: %s\n", length, password);
    printf("===================================================================\n");
}

// Display password statistics
void displayPasswordStatistics(const char *password)
{
    countCharTypes(password);

    int length = strlen(password);
    printf("\n===== Password Statistics ======\n");
    printf("Length: %d\n", length);
    printf("Contains lowercase letters: %s\n", hasLower ? "Yes" : "No");
    printf("Contains uppercase letters: %s\n", hasUpper ? "Yes" : "No");
    printf("Contains digits: %s\n", hasDigit ? "Yes" : "No");
    printf("Contains special characters: %s\n", hasSpecial ? "Yes" : "No");
    printf("\n================================\n");
}

// Display the menu for user options
void displayMenu()
{
    printf("\n\n============== Menu =============\n");
    printf("1. Display password statistics\n");
    printf("2. Generate a password suggestion\n");
    printf("3. Exit\n");
    printf("=================================\n");
    printf("Enter your choice: ");
}

int main()
{

    printf("\n*---------------------------------- MINI PROJECT ----------------------------------*");
    printf("\nSUBJECT NAME: DESIGN AND ANALYSIS OF ALGORITHMS");
    printf("\nSUBJECT NAME: 202045601");
    printf("\nMINI PROJECT TITLE: PASSWORD STRENGHT EVALUATER AND ENHANCER USING GREEDY ALGORITHMS");
    printf("\n\nDeveloped by: SMIT FULTARIYA  <12202080501056> & VRAJ PATEL <12202080501068>");
    printf("\n*----------------------------------------------------------------------------------*\n\n");

    char password[100];
    int strengthPercentage;
    int validPassword = 0;
    int choice, res;
label:
    printf("\nEnter password(or enter 'exit' to quit): ");
    scanf("%99s", password);

    if (strcmp(password, "exit") == 0)
    {
        printf("\n\nExiting.......");
        return 0;
    }
    else
    {
        strengthPercentage = calculateStrengthPercentage(password);

        if (strengthPercentage == -1)
        {
            printf("Password length must be between %d and %d characters. Please try again.\n", MIN_LENGTH, MAX_LENGTH);
        }
        else
        {
            if (strengthPercentage >= 75)
            {
                printf("\nPassword is strong \n");
                do
                {
                label1:
                    displayMenu();
                    scanf("%d", &choice);
                    switch (choice)
                    {
                    case 1:
                        displayPasswordStatistics(password);
                        break;
                    case 2:
                        generateStrongPasswordSuggestion(strlen(password));
                        break;
                    case 3:
                        printf("Exiting...\n");
                        return 0;
                    default:
                        printf("Invalid choice. Please enter a number between 1 and 3.\n");
                        break;
                    }
                } while (choice != 3);
            }

            else
            {
                printf("\nPassword is weak.\n");
                res = provideWeakPasswordSuggestions(password);
                if (res == -1)
                {
                    printf("\nInsufficient space for adding new charcters");
                }
                if (res == 0)
                    goto label;
                if (res == 1)
                    goto label1;
            }
        }
    }

    return 0;
}