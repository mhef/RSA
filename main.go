package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// debug define se o codigo deve imprimir mensagens com informações para debug
// (por exemplo a descricacao das letras, blocos, blocos codificados, etc.)
const debug = false

// mod retorna o resto de a/b de acordo com a definição euclidiana.
//
// Baseado em https://stackoverflow.com/a/43018347
func mod(a int64, b int64) int64 {
	r := a % b
	if (r < 0 && b > 0) || (r > 0 && b < 0) {
		return r + b
	}
	return r
}

// modpow recebe a, b, n e retorna a^b mod n.
//
// Baseado na descrição do algoritimo na especificação do trabalho.
func modpow(a, b, n int64) int64 {
	if b == 1 {
		return a
	}

	x := mod(modpow(a, b/2, n), n)
	if b%2 == 0 {
		return mod((x * x), n)
	}
	return mod(mod((x*x), n)*a, n)
}

// mdc recebe a e b e retorna mdc(a,b)
//
// Baseado no algoritimo de Euclides.
func mdc(a, b int64) int64 {
	if b == 0 {
		return a
	}
	return mdc(b, mod(a, b))
}

// mdcExtended recebe a, b e retorna os coeficientes de
// Bezout, de acordo com o algoritimo de Euclides extendido.
//
// Baseado em https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
func mdcExtended(a, b int64) (c1 int64, c2 int64) {
	oldR, r := a, b
	oldS, s := int64(1), int64(0)
	oldT, t := int64(0), int64(1)

	for r != 0 {
		quotient := oldR / r
		oldR, r = r, oldR-quotient*r
		oldS, s = s, oldS-quotient*s
		oldT, t = t, oldT-quotient*t
	}

	return oldS, oldT
}

// isPrime recebe n e verifica se ele é primo através do pequeno teorema de Fermat.
func isPrime(n int64) bool {
	for a := int64(1); a < 1000000; a++ {
		if mdc(a, n) == 1 {
			// a e p são coprimos
			if modpow(a, n-1, n) != 1 {
				return false
			}
		}
	}

	return true
}

// generateRandomPrime gera um número primo aleatório de valor no máximo 54772.
//
// Utiliza o pequeno teorema de Fermat, como indicado na especificação do trabalho.
func generateRandomPrime() int64 {
	randomByte := make([]byte, 2)
	for {
		// lê 2 bytes aleatórios da fonte criptográfica segura do kernel do SO.
		rand.Read(randomByte)

		// Concatena os dois bytes, formando um número de 16 bits (65535).
		pb := (uint16(randomByte[0]) | (uint16(randomByte[1]) << 8))

		p := int64(pb)
		if p > 54772 {
			// Como especificado na FAQ do trabalho, o valor de n precisa ser no máximo
			// 3 bilhões. Portanto, como uma forma de não atingir o limite, vamos limitar
			// cada numero a ser no máximo sqrt(3 bilhoes) = 54772.
			//
			// Caso o número gerado esteja acima desse limite, gera um novo.
			continue
		}

		// verifica se o número gerado é primo
		if isPrime(p) {
			return p
		}
	}
}

// generateE recebe phi e gera um e aleatório tal que mdc(e, phi) = 1.
func generateE(phi int64) int64 {
	randomByte := make([]byte, 2)
	for {
		// lê 2 byte aleatórios da fonte criptográfica segura do kernel do SO.
		rand.Read(randomByte)

		// Concatena os dois bytes, formando um número de 16 bits (65535).
		eb := (uint16(randomByte[0]) | (uint16(randomByte[1]) << 8))

		e := int64(eb)
		if mdc(e, phi) == 1 {
			return e
		}
	}
}

// genereateRSAKeys gera as chaves RSA publicas e privadas de acordo com a especificação do trabalho.
func genereateRSAKeys() (n, e, d int64) {
	p := generateRandomPrime()
	q := generateRandomPrime()
	n = p * q
	phi := (p - 1) * (q - 1)
	e = generateE(phi)
	s, _ := mdcExtended(e, phi)
	if s < 0 {
		d = s + phi
		return
	}
	d = s
	return
}

// blockSize recebe o n, e retorna o número de digitos que cada bloco pode
// ter.
func blockSize(n int64) int {
	var blockI string
	for {
		bi, _ := strconv.Atoi(blockI + "25")
		if int64(bi) > n {
			break
		}
		blockI += "25"
	}
	return len(blockI)
}

func countDigits(n int64) int {
	return len(fmt.Sprintf("%d", n))
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// decodeMessage recebe a chave publica (n, e) e uma mensagem e então retorna a mensagem codificada
// através da chave.
func encodeMessage(n, e int64, msg string) string {
	ms := make([]string, 0)

	// primeiramente converte cada caractere para numero, se ainda não é
	for _, c := range msg {
		letterDigit := strings.Index(alphabet, string(c))
		// Completa o numero com 0, caso tenha apenas um digito
		letterDigitPadded := fmt.Sprintf("%02d", letterDigit)
		ms = append(ms, letterDigitPadded)
	}

	// gera os blocos
	bSize := blockSize(n)
	blocks := make([]string, 0)
	if debug {
		fmt.Println("Mensagem: ", msg)
		fmt.Println("MS:", ms)
		fmt.Println("BlockSize:", bSize)
	}

	for i := 0; i < len(ms); i += bSize / 2 {
		block := ""
		for j := 0; j < bSize/2; j++ {
			if i+j < len(ms) {
				block += ms[i+j]
			} else {
				// Caso, os caracteres acabem antes do bloco, completa o bloco
				// com o caractere X (indice 23).
				block += "23"
			}
		}
		blocks = append(blocks, block)
	}

	if debug {
		fmt.Println("Blocos: ", blocks)
	}

	// codifica os blocos
	cblocks := make([]string, 0, len(blocks))
	for _, b := range blocks {
		blockInt, _ := strconv.Atoi(b)
		c := modpow(int64(blockInt), e, n)
		// completa o bloco codificado com 0, para que fique do tamanho correto.
		//
		// Aqui nos optamos por completar o bloco codificado com o numero de digitos
		// que n tem, já que é o maior numero de digitos que o bloco codificado pode ter.
		cStr := fmt.Sprintf("%0*d", countDigits(n), int(c))
		cblocks = append(cblocks, cStr)
	}

	if debug {
		fmt.Println("Blocos codificados: ", cblocks)
	}

	// junta os blocos numa string
	encodedResult := ""
	for _, cb := range cblocks {
		encodedResult += cb + " "
	}
	return encodedResult
}

// decodeMessage recebe a chave privada (n, d) e uma mensagem decodidificada
// e então retorna a mensagem decodificada através da chave, se possível.
func decodeMessage(n, d int64, msg string) string {
	// remove os espaços, caso existam
	msg = strings.Replace(msg, " ", "", -1)

	// transforma a mensagem em blocos
	cbSize := countDigits(n)
	cBlocks := make([]string, 0)

	if debug {
		fmt.Println("Mensagem: ", msg)
		fmt.Println("cbSize: ", cbSize)
	}

	for i := 0; i < len(msg); i += cbSize {
		block := ""
		for j := 0; j < cbSize; j++ {
			if i+j >= len(msg) {
				panic("Mensagem codificada não está com os blocos no tamanho correto.")
			}
			block += string(msg[i+j])
		}
		cBlocks = append(cBlocks, block)
	}
	if debug {
		fmt.Println("Blocos codificados: ", cBlocks)
	}

	// decodifica os blocos
	bSize := blockSize(n)
	blocks := make([]string, 0, len(cBlocks))
	for _, b := range cBlocks {
		blockInt, _ := strconv.Atoi(b)
		c := modpow(int64(blockInt), d, n)
		// Completa com 0, caso necessario
		cStr := fmt.Sprintf("%0*d", bSize, int(c))
		blocks = append(blocks, cStr)
	}
	if debug {
		fmt.Println("Blocos decodificados: ", blocks)
	}

	// transforma os blocos em texto
	ret := ""
	for _, b := range blocks {
		for i := 0; i < len(b); i += 2 {
			letter := string(b[i]) + string(b[i+1])
			letterint, _ := strconv.Atoi(letter)
			ret += string(alphabet[letterint])
		}
	}

	return ret
}

// findPrivateKey recebe uma chave publica e retorna uma chave privada atraves
// de forca bruta
func findPrivateKey(n, e int64) int64 {
	var p, q int64
	for i := n - 1; i >= int64(2); i-- {
		if n%i == 0 {
			p = i
			q = n / i
			break
		}
	}

	// encontra d
	phi := (p - 1) * (q - 1)
	s, _ := mdcExtended(e, phi)
	if s < 0 {
		return s + phi
	}
	return s
}

func main() {
	fmt.Println("Escolha a opcao:")
	fmt.Println("1 - Gerar Chaves")
	fmt.Println("2 - Codificar mensagem")
	fmt.Println("3 - Decodificar mensagem")
	fmt.Println("4 - Assinar mensagem")
	fmt.Println("5 - Verificar assinatura mensagem")
	fmt.Println("6 - Descobre chave privada")

	fmt.Print("Digite a opcao: ")

	var n int
	fmt.Scan(&n)

	switch n {
	case 1:
		n, e, d := genereateRSAKeys()
		fmt.Println("Chaves geradas")
		fmt.Println("n:", n)
		fmt.Println("e:", e)
		fmt.Println("d:", d)
		break
	case 2:
		fmt.Println("Insira a chave publica:")
		fmt.Print("n: ")
		var n int64
		fmt.Scan(&n)
		fmt.Print("e: ")
		var e int64
		fmt.Scan(&e)
		fmt.Println("Insira a mensagem:")
		var msg string
		fmt.Scanln(&msg)
		fmt.Println()
		fmt.Print("Resultado: ")
		fmt.Println(encodeMessage(n, e, msg))
		break
	case 3:
		fmt.Println("Insira a chave privada:")
		fmt.Print("n: ")
		var n int64
		fmt.Scan(&n)
		fmt.Print("d: ")
		var d int64
		fmt.Scan(&d)
		fmt.Println("Insira a mensagem codificada:")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		msg := scanner.Text()
		fmt.Println()
		fmt.Print("Resultado: ")
		fmt.Println(decodeMessage(n, d, msg))
	case 4:
		fmt.Println("Insira a chave privada:")
		fmt.Print("n: ")
		var n int64
		fmt.Scan(&n)
		fmt.Print("d: ")
		var d int64
		fmt.Scan(&d)
		fmt.Println("Insira a mensagem a ser assinada:")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		msg := scanner.Text()
		fmt.Println()
		fmt.Print("Assinatura: ")
		fmt.Println(encodeMessage(n, d, msg))
	case 5:
		fmt.Println("Insira a chave publica:")
		fmt.Print("n: ")
		var n int64
		fmt.Scan(&n)
		fmt.Print("e: ")
		var e int64
		fmt.Scan(&e)
		fmt.Println("Insira a assinatura:")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		msg := scanner.Text()
		fmt.Println()
		fmt.Print("Mensagem: ")
		fmt.Println(decodeMessage(n, e, msg))
	case 6:
		fmt.Println("Insira a chave publica:")
		fmt.Print("n: ")
		var n int64
		fmt.Scan(&n)
		fmt.Print("e: ")
		var e int64
		fmt.Scan(&e)
		fmt.Print("Chave privada: ")
		fmt.Println(findPrivateKey(n, e))
	}
}
