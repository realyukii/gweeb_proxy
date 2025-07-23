#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

/*
* the program that analyze the frequency of collision
* for random number generator in 16-bit range.
*
* created as an attempt for generating transaction id of dns query
*/
int main(void)
{
	int prev, cur;
	uint16_t u16prev, u16cur;
	unsigned long long counter;

	srand(time(NULL));
	prev = rand();
	counter = 0;
	while (1) {
		counter++;
		cur = rand();
		u16cur = cur & 0xFFFF;
		u16prev = prev & 0xFFFF;
		if (u16cur == u16prev && counter == 1) {
			printf("\e[1;1H\e[2J");
			printf(
				"current and previous value collide "
				"after %lld times of iteration: %" PRIu16 "\n",
				counter, u16cur
			);
			printf(
				"what the fuck? "
				"collide immediately in the next iteration "
				"of the total 0xFFFF iteration?!!\n"
			);
			counter = 0;
		} else if (counter == 0xFFFF)
			counter = 0;
		prev = cur;
	}
	

	return 0;
}