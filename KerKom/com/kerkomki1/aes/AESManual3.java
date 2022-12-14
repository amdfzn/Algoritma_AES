package com.kerkomki1.aes;
import java.util.*;

public class AESManual3 {
    public static ArrayList<int[][]> keys = new ArrayList<>();

    // method main untuk menjalankan program dan memberikan inputan
    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.print("Masukkan Plain Text : ");
        String plainText = scan.nextLine();
        System.out.print("Masukkan Chiper Key : ");
        String ChiperKey = scan.nextLine();
        System.out.println("------------------------------------");
        Encrypt(plainText, ChiperKey);
        scan.close();
    }

    // method enkripsi plain text
    public static void Encrypt(String input, String key){

        System.out.println("Plain Text : " + input + "\n" + "Chiper Key: " + key + " ");
        System.out.println("------------------------------------");

        // merubah plain text ke matriks
        int[][] inputMatrix = new int[4][4];
        stringToByteMatrix(inputMatrix, input);
        System.out.println("Plain text yang sudah berubah menjadi matriks : ");

        // menampilkan matriks Plain Text
        printMatrix(inputMatrix);

        // merubah chiper key ke matrikx
        int[][] keyMatrix = new int[4][4];
        stringToByteMatrix(keyMatrix, key);
        System.out.println("Chiper Key yang sudah berubah menjadi matriks : ");

        // menampilkan matriks Chiper Key
        printMatrix(keyMatrix);

        // key ekspansi
        generateKeyExpansions(keyMatrix);

        // proses addround key yang pertama yang akan digunakan untuk round berikutnya
        addRoundKey(inputMatrix, keyMatrix);

        // proses enkripsi round dari 0-9
        for(int i = 0; i<9; i++){
            subBytes(inputMatrix);
            shiftRows(inputMatrix);
            mixColumns(inputMatrix);
            addRoundKey(inputMatrix, keys.get(i));
            System.out.println("Round " + i);
            printMatrix(inputMatrix);
        }

        // proses enkripsi round terakhir , mixcolumn tidak digunakan
        subBytes(inputMatrix);
        shiftRows(inputMatrix);
        addRoundKey(inputMatrix, keys.get(9));
        System.out.println("Round " + 9);
        printMatrix(inputMatrix);

        System.out.print("Hasil Enkripsi (Chiper Text): ");
        ByteMatrixToString(inputMatrix);
        System.out.println("------------------------------------");
        System.out.print("Decryption: ");
        Decrpyt(inputMatrix, key);
    }

    private static void keyExpansion(int[][] keyMatrix, int[][] newKey, int index){

        int[][] rcon = {
                {0x01,	0x02,	0x04,	0x08,	0x10,	0x20,	0x40,	0x80,	0x1B,	0x36},
                {0x00,  0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00},
                {0x00,  0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00},
                {0x00,  0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00,   0x00},
        };

        newKey[0][0] = (subByteSingle((byte)keyMatrix[1][3]) & 0xff) ^ keyMatrix[0][0] ^ rcon[0][index];
        newKey[1][0] = (subByteSingle((byte)keyMatrix[2][3]) & 0xff) ^ keyMatrix[1][0] ^ rcon[1][index];
        newKey[2][0] = (subByteSingle((byte)keyMatrix[3][3]) & 0xff) ^ keyMatrix[2][0] ^ rcon[2][index];
        newKey[3][0] = (subByteSingle((byte)keyMatrix[0][3]) & 0xff) ^ keyMatrix[3][0] ^ rcon[3][index];

        newKey[0][1] = keyMatrix[0][1] ^ newKey[0][0];
        newKey[1][1] = keyMatrix[1][1] ^ newKey[1][0];
        newKey[2][1] = keyMatrix[2][1] ^ newKey[2][0];
        newKey[3][1] = keyMatrix[3][1] ^ newKey[3][0];

        newKey[0][2] = keyMatrix[0][2] ^ newKey[0][1];
        newKey[1][2] = keyMatrix[1][2] ^ newKey[1][1];
        newKey[2][2] = keyMatrix[2][2] ^ newKey[2][1];
        newKey[3][2] = keyMatrix[3][2] ^ newKey[3][1];

        newKey[0][3] = keyMatrix[0][3] ^ newKey[0][2];
        newKey[1][3] = keyMatrix[1][3] ^ newKey[1][2];
        newKey[2][3] = keyMatrix[2][3] ^ newKey[2][2];
        newKey[3][3] = keyMatrix[3][3] ^ newKey[3][2];

    }


    public static void generateKeyExpansions(int[][] originalKey){

        int[][] tempKey = new int[4][4];
        keyExpansion(originalKey, tempKey, 0);
        keys.add(tempKey);

        for(int i =1; i< 10; i++){
            tempKey = new int[4][4];
            keyExpansion(keys.get(i-1), tempKey, i);
            keys.add(tempKey);
        }


    }

    // method merubah string ke matrix
    public static void stringToByteMatrix(int[][] matrix, String input) {
        int row = 0;
        int column = 0;

        // merubah yang di inputkan menjadi charArr (Array Krakter)
        for(char c: input.toCharArray())
        {
            matrix[row][column] =  (byte)c;

            if(row == 3)
            {
                row = 0;
                column++;
            }
            else
                row++;
        }
    }


    // method subByte dengan sBox
    public static void subBytes(int[][] inputMatrix){

        // table s-box
        int[][] subBox = {
                {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        for(int i = 0; i < 4; i++)
            for(int j = 0; j < 4; j++){
                int row = inputMatrix[i][j] & 0x0f;
                // right shift >> simbol
                int col = (inputMatrix[i][j] & 0xf0) >> 4;
                inputMatrix[i][j] = subBox[col][row];
            }
    }

    public static byte subByteSingle(byte a){

        int[][] subBox = {
                {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        int row = a & 0x0f;
        int col = (a & 0xf0) >> 4;

        return (byte)subBox[col][row];
    }
    // method yang digunakan untuk shift row
    public static void shiftRows(int[][] inputMatrix){
        swapMatrixElement(inputMatrix, 1, 0, 1, 3);
        swapMatrixElement(inputMatrix, 1, 1, 1, 0);
        swapMatrixElement(inputMatrix, 1, 2, 1, 1);

        swapMatrixElement(inputMatrix, 2, 0, 2, 2);
        swapMatrixElement(inputMatrix, 2, 1, 2, 3);

        swapMatrixElement(inputMatrix, 3, 0, 3, 3);
        swapMatrixElement(inputMatrix, 3, 1, 3, 3);
        swapMatrixElement(inputMatrix, 3, 2, 3, 3);
    }
    // method yang di gunakan untuk mix column
    private static void mixColumns(int[][] matrix) {

        byte[][] temp = new byte[4][4];

        for (int j = 0; j < 4; j++)
            for (int i = 0; i < 4; i++)
                temp[i][j] = (byte)matrix[i][j];

        for(int i = 0; i < 4; i++) {
            matrix[0][i] = (byte) (Galois(temp[0][i], (byte) 2) ^ Galois(temp[1][i], (byte) 3) ^ Galois(temp[2][i], (byte) 1) ^ Galois(temp[3][i], (byte) 1)) & 0xff;
            matrix[1][i] = (byte) (Galois(temp[0][i], (byte) 1) ^ Galois(temp[1][i], (byte) 2) ^ Galois(temp[2][i], (byte) 3) ^ Galois(temp[3][i], (byte) 1)) & 0xff;
            matrix[2][i] = (byte) (Galois(temp[0][i], (byte) 1) ^ Galois(temp[1][i], (byte) 1) ^ Galois(temp[2][i], (byte) 2) ^ Galois(temp[3][i], (byte) 3)) & 0xff;
            matrix[3][i] = (byte) (Galois(temp[0][i], (byte) 3) ^ Galois(temp[1][i], (byte) 1) ^ Galois(temp[2][i], (byte) 1) ^ Galois(temp[3][i], (byte) 2)) & 0xff;
        }
    }

    // method galois yang di gunakan untuk mix column
    private static byte Galois(byte a, byte b) {
        byte returnValue = 0;
        byte temp = 0;

        while (a != 0) {
            if ((a & 1) != 0)
                returnValue = (byte) (returnValue ^ b);
            temp = (byte) (b & 0x80);
            b = (byte) (b << 1);
            if (temp != 0)
                b = (byte) (b ^ 0x1b);
            a = (byte) ((a & 0xff) >> 1);
        }
        return returnValue;
    }
    // method untuk proses AddRoundKey
    public static void addRoundKey(int[][] inputMatrix, int[][] keyMatrix){
        for(int i = 0; i < 4; i++){
            for(int j=0; j <4; j++){
                // ^ merupakan simbol xor
                inputMatrix[i][j] = inputMatrix[i][j] ^ keyMatrix[i][j];
            }
        }
    }

    // method yang di gunakan untuk swap matriks yang nanti nya di pakai di shift coloumn
    public static void swapMatrixElement(int[][] inputMatrix, int row1, int col1, int row2, int col2){
        int temp = inputMatrix[row1][col1];
        inputMatrix[row1][col1] = inputMatrix[row2][col2];
        inputMatrix[row2][col2] = temp;
    }

    // method yang digunakan untuk dekripsi plain text
    public static void Decrpyt(int[][] cipherMatrix, String key){

        // merubah chiper text ke bentuk matrx iks
        int[][] keyMatrix = new int[4][4];
        stringToByteMatrix(keyMatrix, key);
        System.out.println("");
        System.out.println("Chiper text yang di rubah menjadi matriks : ");
        printMatrix(cipherMatrix);

        // proses dekripsi yang pertama untuk digunakan di round berikutnya
        addRoundKey(cipherMatrix, keys.get(9));
        System.out.println("Round " + 9);
        printMatrix(cipherMatrix);
        invShiftRows(cipherMatrix);
        invSubBytes(cipherMatrix);

        // proses dekripsi dari round 9 - 0, secara invers atau terbalik
        for(int i = 8; i>=0; i--){
            addRoundKey(cipherMatrix, keys.get(i));
            invMixColumns(cipherMatrix);
            System.out.println("Round " + i);
            printMatrix(cipherMatrix);
            invShiftRows(cipherMatrix);
            invSubBytes(cipherMatrix);
        }

        // xor antara dekripsi dengan key matriks
        addRoundKey(cipherMatrix, keyMatrix);
        System.out.println("Hasil xor antara hasil dekripsi dengan key matriks : ");
        printMatrix(cipherMatrix);

        // lalu rubah matrik dari byte ke string
        System.out.print("Plain Text : ");
        ByteMatrixToString(cipherMatrix);
    }


    // method merubah matrix menjadi string
    public static void ByteMatrixToString(int[][] matrix) {
        // string builder biasa digunakan  untuk membentuk atau melakukan operasi terhadap objek String
        StringBuilder output = new StringBuilder();
        for (int j = 0; j < 4; j++)
            for (int i = 0; i < 4; i++)
                // metode append, string akan ditambahkan di bagian akhir dari nilai string yang sudah ada.
                output.append((char)matrix[i][j]);

        System.out.println(output.toString());
    }

    // untuk mengetahui isi matriks
    public static void printMatrix(int[][] matrix){
        for(int i = 0;i < 4; i++){
            System.out.print("| ");
            for(int j=0; j <4; j++)
                System.out.print(String.format("%02x", matrix[i][j]) + " ");
            System.out.println("| ");
        }
        System.out.println("------------------------------------");
    }

    // method invers Sub Byte buat dekripsi
    public static void invSubBytes(int[][] inputMatrix){
        // table invers s-box
        int[][] invSubBox = {
                {0x52,	0x09,	0x6a,	0xd5,	0x30,	0x36,	0xa5,	0x38,	0xbf,	0x40,	0xa3,	0x9e,	0x81,	0xf3,	0xd7,	0xfb},
                {0x7c,	0xe3,	0x39,	0x82,	0x9b,	0x2f,	0xff,	0x87,	0x34,	0x8e,	0x43,	0x44,	0xc4,	0xde,	0xe9,	0xcb},
                {0x54,	0x7b,	0x94,	0x32,	0xa6,	0xc2,	0x23,	0x3d,	0xee,	0x4c,	0x95,	0x0b,	0x42,	0xfa,	0xc3,	0x4e},
                {0x08,	0x2e,	0xa1,	0x66,	0x28,	0xd9,	0x24,	0xb2,	0x76,	0x5b,	0xa2,	0x49,	0x6d,	0x8b,	0xd1,	0x25},
                {0x72,	0xf8,	0xf6,	0x64,	0x86,	0x68,	0x98,	0x16,	0xd4,	0xa4,	0x5c,	0xcc,	0x5d,	0x65,	0xb6,	0x92},
                {0x6c,	0x70,	0x48,	0x50,	0xfd,	0xed,	0xb9,	0xda,	0x5e,	0x15,	0x46,	0x57,	0xa7,	0x8d,	0x9d,	0x84},
                {0x90,	0xd8,	0xab,	0x00,	0x8c,	0xbc,	0xd3,	0x0a,	0xf7,	0xe4,	0x58,	0x05,	0xb8,	0xb3,	0x45,	0x06},
                {0xd0,	0x2c,	0x1e,	0x8f,	0xca,	0x3f,	0x0f,	0x02,	0xc1,	0xaf,	0xbd,	0x03,	0x01,	0x13,	0x8a,	0x6b},
                {0x3a,	0x91,	0x11,	0x41,	0x4f,	0x67,	0xdc,	0xea,	0x97,	0xf2,	0xcf,	0xce,	0xf0,	0xb4,	0xe6,	0x73},
                {0x96,	0xac,	0x74,	0x22,	0xe7,	0xad,	0x35,	0x85,	0xe2,	0xf9,	0x37,	0xe8,	0x1c,	0x75,	0xdf,	0x6e},
                {0x47,	0xf1,	0x1a,	0x71,	0x1d,	0x29,	0xc5,	0x89,	0x6f,	0xb7,	0x62,	0x0e,	0xaa,	0x18,	0xbe,	0x1b},
                {0xfc,	0x56,	0x3e,	0x4b,	0xc6,	0xd2,	0x79,	0x20,	0x9a,	0xdb,	0xc0,	0xfe,	0x78,	0xcd,	0x5a,	0xf4},
                {0x1f,	0xdd,	0xa8,	0x33,	0x88,	0x07,	0xc7,	0x31,	0xb1,	0x12,	0x10,	0x59,	0x27,	0x80,	0xec,	0x5f},
                {0x60,	0x51,	0x7f,	0xa9,	0x19,	0xb5,	0x4a,	0x0d,	0x2d,	0xe5,	0x7a,	0x9f,	0x93,	0xc9,	0x9c,	0xef},
                {0xa0,	0xe0,	0x3b,	0x4d,	0xae,	0x2a,	0xf5,	0xb0,	0xc8,	0xeb,	0xbb,	0x3c,	0x83,	0x53,	0x99,	0x61},
                {0x17,	0x2b,	0x04,	0x7e,	0xba,	0x77,	0xd6,	0x26,	0xe1,	0x69,	0x14,	0x63,	0x55,	0x21,	0x0c,	0x7d}
        };

        for(int i = 0; i < 4; i++)
            for(int j = 0; j < 4; j++){
                int row = inputMatrix[i][j] & 0x0f;
                int col = (inputMatrix[i][j] & 0xf0) >> 4;
                inputMatrix[i][j] = invSubBox[col][row];
            }
    }

    // method yang di gunakan untuk invers shift row
    public static void invShiftRows(int[][] inputMatrix){

        swapMatrixElement(inputMatrix, 1, 3, 1, 2);
        swapMatrixElement(inputMatrix, 1, 2, 1, 1);
        swapMatrixElement(inputMatrix, 1, 1, 1, 0);

        swapMatrixElement(inputMatrix, 2, 3, 2, 1);
        swapMatrixElement(inputMatrix, 2, 2, 2, 0);

        swapMatrixElement(inputMatrix, 3, 2, 3, 0);
        swapMatrixElement(inputMatrix, 3, 3, 3, 2);
        swapMatrixElement(inputMatrix, 3, 0, 3, 1);
    }

    // method yang di gunakan untuk invers mix columnt
    private static void invMixColumns(int[][] matrix) {

        byte[][] temp = new byte[4][4];

        for (int j = 0; j < 4; j++)
            for (int i = 0; i < 4; i++)
                temp[i][j] = (byte)matrix[i][j];

        for(int i = 0; i < 4; i++) {
            matrix[0][i] = (byte) (Galois(temp[0][i], (byte) 0x0e) ^ Galois(temp[1][i], (byte) 0x0b) ^ Galois(temp[2][i], (byte) 0x0d) ^ Galois(temp[3][i], (byte) 0x09)) & 0xff;
            matrix[1][i] = (byte) (Galois(temp[0][i], (byte) 0x09) ^ Galois(temp[1][i], (byte) 0x0e) ^ Galois(temp[2][i], (byte) 0x0b) ^ Galois(temp[3][i], (byte) 0x0d)) & 0xff;
            matrix[2][i] = (byte) (Galois(temp[0][i], (byte) 0x0d) ^ Galois(temp[1][i], (byte) 0x09) ^ Galois(temp[2][i], (byte) 0x0e) ^ Galois(temp[3][i], (byte) 0x0b)) & 0xff;
            matrix[3][i] = (byte) (Galois(temp[0][i], (byte) 0x0b) ^ Galois(temp[1][i], (byte) 0x0d) ^ Galois(temp[2][i], (byte) 0x09) ^ Galois(temp[3][i], (byte) 0x0e)) & 0xff;
        }
    }

}
