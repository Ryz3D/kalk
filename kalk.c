/*

x = (-) (a[]) / (b[])

min: 1 / (2 ^ (32 * UINT32_MAX))
max: (2 ^ (32 * UINT32_MAX)) / 1

*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <malloc.h>
#include <math.h>

#if defined(WIN)
#define ENDL "\r\n"
#elif defined(UNIX)
#define ENDL "\n"
#else
#warning "Please specify platform using -D WIN or -D UNIX"
#define ENDL "\n"
#endif

#define KALK_MALLOC(size) malloc(size)
#define KALK_FREE(pointer) free(pointer)
#define KALK_CLEAR(pointer, size) memset(pointer, 0, size)
#define KALK_MEMCOPY(dst, src, size) memcpy(dst, src, size)

#define KALK_MIN(a, b) (((a) <= (b)) ? (a) : (b))
#define KALK_MAX(a, b) (((a) >= (b)) ? (a) : (b))

typedef enum kalk_number_flag {
    KALK_NUMBER_FLAG_NEGATIVE = 0,
    KALK_NUMBER_FLAG_COMPLEX = 0,
} kalk_number_flag_t;

typedef struct kalk_number kalk_number_t;

typedef struct kalk_number {
    uint8_t flags;
    kalk_number_t *next;
    uint32_t length1;
    uint32_t length2;
    uint32_t data;
} kalk_number_t;

kalk_number_t *kalk_number_alloc(uint32_t length1, uint32_t length2) {
    if (length1 == 0) {
        length1 = 1;
    }
    if (length2 == 0) {
        length2 = 1;
    }
    uint32_t number_size = sizeof(kalk_number_t) + (length1 + length2 - 1) * sizeof(uint32_t);
    kalk_number_t *num = KALK_MALLOC(number_size);
    if (num == NULL) {
        printf("(kalk_init_number) ERROR: out of memory! could not allocate new number" ENDL);
        return NULL;
    }
    num->flags = 0;
    num->next = NULL;
    num->length1 = length1;
    num->length2 = length2;
    KALK_CLEAR(&num->data, length1 + length2);
    (&num->data)[length1] = 1; // 0 / 1
    return num;
}

void kalk_number_free(kalk_number_t *num) {
    if (num == NULL) {
        return;
    }
    while (num->next != NULL) {
        kalk_number_t *num_last = num;
        kalk_number_t *num_entry = num->next;
        while (num_entry->next != NULL) {
            num_last = num_entry;
            num_entry = num_entry->next;
        }
        num_last->next = NULL;
        KALK_FREE(num_entry);
    }
    KALK_FREE(num);
}

uint64_t kalk_intlist_add_len(uint64_t a_bits, uint64_t b_bits) {
    return KALK_MAX(a_bits, b_bits) + 1;
}

void kalk_intlist_add(uint32_t *a, uint32_t a_len, uint32_t *b, uint32_t b_len, uint32_t *c, uint32_t c_len) {
    uint8_t carry = 0;
    for (uint32_t i = 0; i < c_len; i++) {
        uint32_t op1 = i < a_len ? a[i] : 0;
        uint32_t op2 = i < b_len ? b[i] : 0;
        c[i] = op1 + op2 + carry;
        if (carry) {
            if (c[i] <= op1) {
                carry = 1;
            }
        } else {
            if (c[i] < op1) {
                carry = 1;
            }
        }
    }
}

uint64_t kalk_intlist_mul_len(uint64_t a_bits, uint64_t b_bits) {
    return a_bits + b_bits;
}

void kalk_intlist_mul(uint32_t *a, uint32_t a_len, uint32_t *b, uint32_t b_len, uint32_t *c, uint32_t c_len) {
    // a binary 1 is equal to the other number shifted to this position added to the result
    // len1+len2 should be allocated, iterate over b bits, if true add shifted a bits (all u32 in []) to result -> max. << is b MSB
    for (uint32_t i = 0; i < c_len; i++) {
        c[i] = 0;
    }


    // TODO: test this with random values and binary output, especially left shift indices and merging
    uint64_t left_shift = 0;
    uint8_t carry = 0;
    for (uint32_t i = 0; i < c_len; i++) {
        uint32_t op1 = i < a_len ? a[i] : 0;
        int64_t index_b1 = (int64_t)i - (int64_t)(left_shift / 32);
        int64_t index_b2 = index_b1 - 1;
        uint32_t op2 = ((index_b1 > 0 && index_b1 < b_len) ? (b[index_b1] << (left_shift % 32)) : 0) |
                       ((index_b2 > 0 && index_b2 < b_len && left_shift % 32 != 0) ? (b[index_b2] >> (31 - left_shift % 32)) : 0);
        // TODO: consider existing c[i]
        c[i] = op1 + op2 + carry;
        if (carry) {
            if (c[i] <= op1) {
                carry = 1;
            }
        } else {
            if (c[i] < op1) {
                carry = 1;
            }
        }
    }
}

kalk_number_t *kalk_number_strip_length(kalk_number_t *num) {
    uint32_t empty1;
    for (empty1 = 0; empty1 < num->length1; empty1++) {
        if ((&num->data)[num->length1 - 1 - empty1] != 0) {
            break;
        }
    }
    uint32_t empty2;
    for (empty2 = 0; empty2 < num->length2; empty2++) {
        if ((&num->data)[num->length1 + num->length2 - 1 - empty2] != 0) {
            break;
        }
    }
    if (empty1 == 0 && empty2 == 0) {
        return num;
    }
    kalk_number_t *num2 = kalk_number_alloc(num->length1 - empty1, num->length2 - empty2);
    if (num2 == NULL) {
        return num;
    }
    num2->flags = num->flags;
    num2->next = num->next;
    KALK_MEMCOPY(&num2->data, &num->data, num2->length1);
    KALK_MEMCOPY(&num2->data + num2->length1, &num->data + num->length1, num2->length2);
    kalk_number_free(num);
    return num2;
}

kalk_number_t *kalk_number_reduce_divisor(kalk_number_t *num) {
    // TODO: minimum of prime factors -> gcd
    // kalk_number_free(num);
    return num;
}

kalk_number_t *kalk_number_cleanup(kalk_number_t *num) {
    kalk_number_t *num2 = kalk_number_strip_length(num);
    if (num2 == NULL) {
        return num;
    }
    num2 = kalk_number_reduce_divisor(num2);
    if (num2 == NULL) {
        return num;
    }
    return num2;
}

uint64_t kalk_number_get_effective_bits1(kalk_number_t *num) {
    uint64_t empty_bits;
    for (empty_bits = 0; empty_bits < (uint64_t)num->length1 * 32 - 1; empty_bits++) {
        uint32_t val = (&num->data)[num->length1 - 1 - empty_bits / 32];
        if (((val >> (31 - empty_bits % 32)) & 1) != 0) {
            break;
        }
    }
    return (uint64_t)num->length1 * 32 - empty_bits;
}

uint64_t kalk_number_get_effective_bits2(kalk_number_t *num) {
    uint64_t empty_bits;
    for (empty_bits = 0; empty_bits < (uint64_t)num->length2 * 32 - 1; empty_bits++) {
        uint32_t val = (&num->data)[num->length1 + num->length2 - 1 - empty_bits / 32];
        if (((val >> (31 - empty_bits % 32)) & 1) != 0) {
            break;
        }
    }
    return (uint64_t)num->length2 * 32 - empty_bits;
}

kalk_number_t *kalk_number_from_int(int64_t i) {
    uint8_t negative = i < 0;
    uint64_t i_abs = negative ? -i : i;
    kalk_number_t *num = kalk_number_alloc((i_abs >> 32) ? 2 : 1, 1);
    if (num == NULL) {
        return NULL;
    }
    if (negative) {
        num->flags |= (1 << KALK_NUMBER_FLAG_NEGATIVE);
    }
    (&num->data)[0] = i_abs & 0xFFFFFFFF;
    if (i_abs >> 32) {
        (&num->data)[1] = i_abs >> 32;
    }
    (&num->data)[num->length1 + 0] = 1;
    return num;
}

int64_t kalk_number_to_int(kalk_number_t *num) {
    num = kalk_number_cleanup(num);

    if (num == NULL) {
        return 0;
    }
    if (num->length2 > 2 || num->length1 == 0) {
        return 0;
    }
    if (num->length2 == 0) {
        printf("(kalk_number_to_int) ERROR: invalid number (length2 == 0)" ENDL);
        return 0;
    }
    uint64_t a = (&num->data)[0];
    uint64_t b = (&num->data)[num->length1];
    if (num->length1 > 1) {
        a |= ((uint64_t)(&num->data)[1] << 32);
    }
    if (num->length2 > 1) {
        b |= ((uint64_t)(&num->data)[num->length1 + 1] << 32);
    }

    uint64_t i_abs = a / b;
    if (i_abs & (1ULL << 63)) {
        printf("(kalk_number_to_int) WARNING: truncating highest (64th) bit" ENDL);
        i_abs &= ~(1ULL << 63);
    }
    return (num->flags & (1 << KALK_NUMBER_FLAG_NEGATIVE)) ? -(int64_t)i_abs : (int64_t)i_abs;
}

kalk_number_t *kalk_number_subtract_single(kalk_number_t *a, kalk_number_t *b);

kalk_number_t *kalk_number_add_single(kalk_number_t *a, kalk_number_t *b) {
    // TODO: use effective_bits for length
    // TODO: respect fractions (same denominator)
    // TODO: strip length

    // TODO: respect sign
    //   a &  b -> a + b
    //  -a &  b -> b - a
    //   a & -b -> a - b
    //  -a & -b -> -(a + b)
    uint32_t longest_length1 = a->length1 >= b->length1 ? a->length1 : b->length1;
    kalk_number_t *c = kalk_number_alloc(longest_length1, a->length2);
    if (c == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < longest_length1; i++) {
        uint32_t op1 = i < a->length1 ? (&a->data)[i] : 0;
        uint32_t op2 = i < b->length1 ? (&b->data)[i] : 0;
        (&c->data)[i] = op1 + op2;
    }
    return c;
}

kalk_number_t *kalk_number_subtract_single(kalk_number_t *a, kalk_number_t *b) {
    return NULL;
}

kalk_number_t *kalk_list_add(kalk_number_t *a, kalk_number_t *b) {
    if (a == NULL || b == NULL) {
        return kalk_number_from_int(0);
    }
    kalk_number_t *c = NULL;
    do {
        if (c == NULL) {
            c = kalk_number_add_single(a, b);
        } else {
            c->next = kalk_number_add_single(a, b);
            c = c->next;
        }
        if (c == NULL) {
            return NULL;
        }
        a = a->next;
        b = b->next;
    } while (a != NULL && b != NULL);
    return c;
}

uint32_t kalk_list_length(kalk_number_t *list) {
    uint32_t length;
    for (length = 1; list->next != NULL; list = list->next) {
        length++;
    }
    return length;
}

kalk_number_t *kalk_list_index(kalk_number_t *list, uint32_t index) {
    for (; index > 0; index--) {
        list = list->next;
        if (list == NULL) {
            return NULL;
        }
    }
    return list;
}

void kalk_number_debug_print(kalk_number_t *num) {
    if (num == NULL) {
        printf("(num @ NULL)" ENDL);
    }
    uint32_t i_abs = 0;
    uint8_t i_abs_valid = 0;
    double f_abs = 0;
    uint8_t f_abs_valid = 0;
    uint64_t bits1 = kalk_number_get_effective_bits1(num);
    uint64_t bits2 = kalk_number_get_effective_bits2(num);
    if (bits1 <= 32 && bits2 <= 32 && bits2 < bits1) {
        uint32_t i1 = (&num->data)[0];
        uint32_t i2 = (&num->data)[num->length1];
        if (i1 % i2 == 0) {
            i_abs = i1 / i2;
            i_abs_valid = 1;
        } else {
            f_abs = (double)i1 / (double)i2;
            f_abs_valid = 1;
        }
    }
    printf("(num @ %p) next=%p (listlen=%-4lu) f=0x%02X l1=%-3lu l2=%-3lu b1=%-4llu b2=%-4llu ",
        num, num->next, kalk_list_length(num), num->flags, num->length1, num->length2, bits1, bits2);
    if (bits1 <= 32 && (&num->data)[0] == 0) {
        printf("0" ENDL);
    } else if (i_abs_valid) {
        printf("int32=%c%lu" ENDL, num->flags & (1 << KALK_NUMBER_FLAG_NEGATIVE) ? '-' : '+', i_abs);
    } else if (f_abs_valid) {
        printf("double=%c%lf" ENDL, num->flags & (1 << KALK_NUMBER_FLAG_NEGATIVE) ? '-' : '+', f_abs);
    } else {
        // TODO: double approximation
        printf("%c", num->flags & (1 << KALK_NUMBER_FLAG_NEGATIVE) ? '-' : '+');
        if (bits1 <= 32) {
            printf("%lu", (&num->data)[0]);
        } else {
            printf("(too big)");
        }
        printf(" / ");
        if (bits2 <= 32) {
            printf("%lu", (&num->data)[num->length1]);
        } else {
            printf("(too big)");
        }
        printf("\t(2^%lli <= x <= 2^%lli)", (int64_t)bits1 - (int64_t)bits2 - 1, (int64_t)bits1 - (int64_t)bits2 + 1);
        int64_t approx_pow_10_1 = ((int64_t)bits1 - (int64_t)bits2 - 1) * 30103 / 100000; // ln(2) / ln(10)
        int64_t approx_pow_10_2 = ((int64_t)bits1 - (int64_t)bits2 + 1) * 30103 / 100000;
        if (approx_pow_10_1 == approx_pow_10_2) {
            printf("\t(10^%lli)" ENDL, approx_pow_10_1);
        } else {
            printf("\t(10^%lli <= x <= 10^%lli)" ENDL, approx_pow_10_1, approx_pow_10_2);
        }
    }
}

int main(int argc, char *argv[]) {
    kalk_number_t *a = kalk_number_from_int(640000000);
    kalk_number_t *b = kalk_number_from_int(3700000000);
    kalk_number_t *c = kalk_list_add(a, b);
    kalk_number_debug_print(a);
    kalk_number_debug_print(b);
    kalk_number_debug_print(c);
    printf("c=%lli" ENDL, kalk_number_to_int(c));
    kalk_number_free(a);
    kalk_number_free(b);
    kalk_number_free(c);
    return 0;
}
