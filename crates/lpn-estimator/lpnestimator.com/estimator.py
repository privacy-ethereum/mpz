# Code taken from https://github.com/RabbitCabbage/LPN-Estimator/blob/main/home/estimator.py
# with slight adaptations to improve linting

import math
import numpy as np
import decimal

import sys
import re
from decimal import Decimal

decimal.getcontext().prec = 170
log10Two = decimal.Decimal(2).log10()


# com: Combination calculator (n choose m calculator)
def com(n, m):
    decimal.getcontext().prec = 170

    Min = min(m, n - m)
    result = decimal.Decimal(1)
    for j in range(0, Min):
        result = result * decimal.Decimal(n - j) / decimal.Decimal(Min - j)

    return result


# Gauss: Calculator for the cost of Pooled Gauss
def Gauss(N, k, t):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    # 2^pp = the probability of guessing successfully in one iteration
    pp = com(N - k, t).log10() / log10Two - (com(N, t).log10() / log10Two)

    # T = the cost of inverting a matrix via Strassen’s algorithm
    if N - k > k:
        T = pow(k, 2.8)
    else:
        T = pow(N - k, 2.8)

    #print("    Gauss(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  "+str(np.log2(T) - float(pp)))
    return np.log2(T) - float(pp)


##############          ISD against LPN over F_2, including SD_ISD and BJMM_ISD          ###################

######     SD_ISD: Calculator for the cost of SD-ISD   #####

# sub_SD_ISD: Calculator for the cost of SD-ISD given additional parameters p and l
def sub_SD_ISD(N, k, t, l, p):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    # make p and l reasonable: both p and k+l are positive even number
    l = int((k + l) / 2) * 2 - k + 2
    p = int(p / 2) * 2

    L0 = com(int((k + l) / 2), int(p / 2))
    logL0 = L0.log10() / log10Two
    logS = logL0 * 2 - l

    # quickly break, since the cost should be larger than logL0 and logS
    if logL0 > 230:
        return 230
    if logS > 230:
        return 230

    S = decimal.Decimal(2) ** logS

    if N - k - l < 1:
        return 23333

    # T1: the cost of one iteration
    Tgauss = decimal.Decimal((N - k - l) * N) / decimal.Decimal(np.log2(N - k - l))
    T1 = Tgauss + 2 * L0 + 2 * S
    T1 = T1 * decimal.Decimal(N)

    # 2^pp = the probability of guessing successfully in one iteration
    #Deno = (com(N, t).log10() / log10Two)
    #if Deno > N - k:
    #    Deno = N - k
    #pp = com(N - k - l, t - p).log10() / log10Two - Deno
    #pp = pp + l + logS

    # 2^pp = the probability of guessing successfully in one iteration
    pp = com(N - k - l, t - p).log10() / log10Two - (com(N, t).log10() / log10Two)
    pp = pp + l + logS

    # quickly break, since the probability should be smaller than 1
    if pp >= 0:
        return 230

    return float(T1.log10() / log10Two - pp)


# min_SD_ISD: Calculator for the cost of SD-ISD given additional parameters p based on ternary search
# Note: the result of sub_SD_ISD convex in l
def min_SD_ISD(N, k, t, p):
    start = 1
    end = int((N - k - 8))

    Tstart = sub_SD_ISD(N, k, t, start, p)
    Tend = sub_SD_ISD(N, k, t, end, p)

    min = Tstart

    while end - start > 30:
        mid1 = int((end - start) / 3) + start
        mid2 = end - int((end - start) / 3)

        Tmid1 = sub_SD_ISD(N, k, t, mid1, p)
        Tmid2 = sub_SD_ISD(N, k, t, mid2, p)

        if Tmid1 > Tmid2:
            start = mid1
            min = Tmid2
        else:
            end = mid2
            min = Tmid1

    if start < 10:
        start = 0
    else:
        start = start - 10

    for l in range(start, end + 10, 1):
        T = sub_SD_ISD(N, k, t, l, p)
        if T <= min:
            min = T

    return min


# SD_ISD: Calculator for the cost of SD-ISD invoking min_SD_ISD
# Note that the result of sub_SD_ISD convex in p and l
def SD_ISD(N, k, t):
    wholemin = sub_SD_ISD(N, k, t, 0, 0)
    for p in range(int(t / 2)):
        min = min_SD_ISD(N, k, t, p)
        if min <= wholemin:
            wholemin = min
        if min > wholemin + 30:
            break
    #print("    SD_ISD_2(N, k, t )   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(wholemin))
    return wholemin


######     BJMM_ISD: Calculator for the cost of BJMM_ISD    #####

# sub_BJMM_ISD: Calculator for the cost of BJMM_ISD given additional parameters p2, l, e1, e2, r1 and r2
def sub_BJMM_ISD(N, k, t, p2, l, e1, e2, r1, r2, localmin):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    # make p2 and l reasonable: both p2 and k+l are positive even number
    l = int((k + l) / 2) * 2 - k + 2
    p2 = int(p2 / 2) * 2
    p1 = 2 * (p2 - e2)
    p = 2 * (p1 - e1)

    S3 = com(int((k + l) / 2), int(p2 / 2))
    logS3 = S3.log10() / log10Two

    logC3 = logS3 * 2 - r2
    C3 = decimal.Decimal(2) ** logC3

    S2 = C3
    logC2 = 2 * logC3 - r1

    C2 = decimal.Decimal(2) ** logC2

    logmu2 = com(p2, e2).log10() / log10Two + (com(k + l - p2, p2 - e2).log10() / log10Two)
    logmu2 = logmu2 - com(k + l, p2).log10() / log10Two
    logS11 = logmu2 + logC2
    logS12 = com(k + l, p1).log10() / log10Two - (r1 + r2)
    logS1 = logS11
    if logS11 > logS12:
        logS1 = logS12
    S1 = decimal.Decimal(2) ** logS1

    logC1 = logS1 * 2 - l + r1 + r2
    C1 = decimal.Decimal(2) ** logC1

    logmu1 = com(p1, e1).log10() / log10Two + (com(k + l - p1, p1 - e1).log10() / log10Two)
    logmu1 = logmu1 - com(k + l, p1).log10() / log10Two
    logS01 = logmu1 + logC1
    logS02 = com(k + l, p).log10() / log10Two - l
    logS0 = logS01
    if logS01 > logS02:
        logS0 = logS02

    # quickly break, since the cost should be larger than logS3, logC3 and logC2
    if logS3 > localmin:
        return 230
    if logC3 > localmin:
        return 230
    if logC2 > localmin:
        return 230

    # T1: the cost of one iteration
    Tgauss = decimal.Decimal((N - k - l) * N) / decimal.Decimal(np.log2(N - k - l))
    T1 = Tgauss + 8 * S3 + 4 * C3 + 2 * C2 + 2 * C1
    T1 = T1 * decimal.Decimal(N)
    logT1 = T1.log10() / log10Two

    # 2^pp = the probability of guessing successfully in one iteration

    #Deno = (com(N, t).log10() / log10Two)
    #if Deno > N - k:
    #    Deno = N - k
    #pp = com(N - k - l, t - p).log10() / log10Two - Deno
    #pp = pp + l + logS0

    # 2^pp = the probability of guessing successfully in one iteration
    pp = com(N - k - l, t - p).log10() / log10Two + l + logS0
    pp = pp - (com(N, t).log10() / log10Two)


    #pp = com(N - k - l, t - p).log10() / log10Two + l + logS0
    #pp = pp - (com(N, t).log10() / log10Two)

    # quickly break, since the probability should be smaller than 1
    if pp >= 0:
        return 223

    return float(logT1 - pp)


# min_sub_BJMM_ISD: Calculator for the cost of BJMM_ISD given additional parameters p2, l
# Note that the the optimal parameter estimation relies on Hamdaoui and Sendrier "A non asymptotic analysis of information set decoding"
def min_sub_BJMM_ISD(N, k, t, p2, l):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    # We focus on the LPN problem whose bit security is smaller than 230
    localmin = 230

    for e2 in range(p2):
        p1 = 2 * (p2 - e2)

        start_e1 = max(0, p1 - int(t / 2))
        if p1 < start_e1:
            break

        for e1 in range(start_e1, p1):
            p = 2 * (p1 - e1)

            term1 = com(int((k + l) / 2), int(p2 / 2)).log10() / log10Two
            term2 = com(k + l, p1).log10() / log10Two
            logmu2 = com(p2, e2).log10() / log10Two + (com(k + l - p2, p2 - e2).log10() / log10Two)
            logmu2 = logmu2 - (com(k + l, p2).log10() / log10Two)
            logmu2 = logmu2 + 4 * term1 - term2
            optimal_r2 = int(logmu2)

            if optimal_r2 < 0:
                optimal_r2 = 0
            if optimal_r2 >= l:
                optimal_r2 = l - 1

            term3 = com(p1, e1).log10() / log10Two + (com(k + l - p1, p1 - e1).log10() / log10Two)
            term4 = term3 + (com(k + l, p1).log10() / log10Two) - (com(k + l, p).log10() / log10Two)
            optimal_r1 = int(term4) - optimal_r2

            if optimal_r1 < 0:
                optimal_r1 = 0
            if optimal_r2 + optimal_r1 >= l:
                optimal_r1 = l - optimal_r2 - 1
            minT = sub_BJMM_ISD(N, k, t, p2, l, e1, e2, optimal_r1, optimal_r2, localmin)

            if minT < localmin:
                localmin = minT

    return localmin


# min_BJMM_ISD: Calculator for the cost of BJMM_ISD given additional parameters p2 based on ternary search
# Note: the result of min_sub_BJMM_ISD convex in l
def min_BJMM_ISD(N, k, t, p2):
    start = 0
    end = int((N - k - 2) / 8)

    Tstart = min_sub_BJMM_ISD(N, k, t, p2, start)

    min = Tstart

    while end - start > 10:
        mid1 = int((end - start) / 3) + start
        mid2 = end - int((end - start) / 3)

        Tmid1 = min_sub_BJMM_ISD(N, k, t, p2, mid1)
        Tmid2 = min_sub_BJMM_ISD(N, k, t, p2, mid2)

        if Tmid1 > Tmid2:
            start = mid1
            min = Tmid2
        else:
            end = mid2
            min = Tmid1

    if start < 5:
        start = 0
    else:
        start = start - 5

    for l in range(start, end + 5, 1):
        T = min_sub_BJMM_ISD(N, k, t, p2, l)
        if T <= min:
            min = T

    return min


# SD_ISD: Calculator for the cost of SD-ISD invoking min_BJMM_ISD
# Note that the result of min_BJMM_ISD convex in p2
def BJMM_ISD(N, k, t):
    wholemin = 230
    min = wholemin
    for p2 in range(0, int(t), 2):
        min = min_BJMM_ISD(N, k, t, p2)

        # print("p2=" + str(p2))
        # print("min="+ str(min))

        if min < wholemin:
            wholemin = min

        if min > wholemin + 8:
            break

    #print("    BJMM_ISD(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(wholemin) )
    return wholemin


##############       sub_SD_ISDq:  Calculator for the cost of ISD_ISD against LPN over F_q          ###################

# sub_SD_ISDq: Calculator for the cost of SD-ISD over F_q given additional parameters p and l
def sub_SD_ISDq(N, k, t, q, l, p):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    # make p and l reasonable: both p and k+l are positive even number
    l = int((k + l) / 2) * 2 - k + 2
    p = int(p / 2) * 2

    L0 = com(int((k + l) / 2), int(p / 2)) * decimal.Decimal(pow(q - 1, int(p / 2)))
    logL0 = com(int((k + l) / 2), int(p / 2)).log10() / log10Two + decimal.Decimal(int(p / 2)) * (
                decimal.Decimal(q - 1).log10() / log10Two)

    logS = 2 * logL0 - decimal.Decimal(l) * (decimal.Decimal(q).log10() / log10Two)
    S = decimal.Decimal(2) ** logS

    # We focus on the LPN problem whose bit security is smaller than 230
    # quickly break, since the cost should be larger than logL0 and logS
    if logS > 230:
        return 230
    if logL0 > 230:
        return 230

    # T1: the cost of one iteration
    Tgauss = decimal.Decimal((N - k - l) * N) / decimal.Decimal(np.log2(N - k - l))
    T1 = Tgauss + 2 * L0 + 2 * S
    T1 = T1 * decimal.Decimal(N)
    logT1 = T1.log10() / log10Two

    # 2^pp = the probability of guessing successfully in one iteration

    # Deno = (com(N, t).log10() / log10Two)
    # if Deno > N - k:
    # Deno = N - k


    pp = com(N - k - l, t - p).log10() / log10Two - (com(N, t).log10() / log10Two)
    pp = pp + decimal.Decimal(l) * (decimal.Decimal(q).log10() / log10Two)
    pp = pp - decimal.Decimal(p) * (decimal.Decimal(q - 1).log10() / log10Two)
    pp = pp + logS

    #Deno = (com(N, t).log10() / log10Two)
    #if Deno > N - k:
        #Deno = N - k
    #pp = com(N - k - l, t - p).log10() / log10Two - Deno
    #pp = pp + l + logS0


    #pp = com(N - k - l, t - p).log10() / log10Two - com(N, t).log10()
    #pp = pp + decimal.Decimal(l) * (decimal.Decimal(q).log10() / log10Two)
    #pp = pp - decimal.Decimal(p) * (decimal.Decimal(q - 1).log10() / log10Two)
    #pp = pp + logS

    # quickly break, since the probability should be smaller than 1
    if pp >= 0:
        return 230

    return float(logT1 - pp)


# min_SD_ISDq: Calculator for the cost of SD-ISDq given additional parameters p based on ternary search
# Note: the result of sub_SD_ISDq convex in l
def min_SD_ISDq(N, k, t, q, p):
    start = 1
    end = int((N - k - 8))

    Tstart = sub_SD_ISDq(N, k, t, q, start, p)
    # Tend = sub_SD_ISDq(N, k, t,q, end,p)

    min = Tstart

    while end - start > 30:
        mid1 = int((end - start) / 3) + start
        mid2 = end - int((end - start) / 3)

        Tmid1 = sub_SD_ISDq(N, k, t, q, mid1, p)
        Tmid2 = sub_SD_ISDq(N, k, t, q, mid2, p)

        if Tmid1 > Tmid2:
            start = mid1
            min = Tmid2
        else:
            end = mid2
            min = Tmid1

    if start < 10:
        start = 0
    else:
        start = start - 10

    for l in range(start, end + 10, 1):
        T = sub_SD_ISDq(N, k, t, q, l, p)
        if T <= min:
            min = T

    return min


# SD_ISD: Calculator for the cost of SD-ISD invoking min_SD_ISD
# Note that the result of sub_SD_ISD convex in p and l
def SD_ISD_q(N, k, t, q):
    wholemin = sub_SD_ISDq(N, k, t, q, 0, 0)
    for p in range(int(t / 2)):
        min = min_SD_ISDq(N, k, t, q, p)

        if min <= wholemin:
            wholemin = min
        if min > wholemin + 30:
            break

    T1 = Gauss(N, k, t)
    if wholemin > T1:
        wholemin = T1

    #print("    SD_ISD_q(N, k, t, q)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(wholemin))
    return wholemin


##############          ISD against LPN over Z_{2^lambda}, including SD_ISD and BJMM_ISD          ###################

def SD_ISD_lam(N, k, t, lam):
    w = int(t * pow(2, lam - 1) / (pow(2, lam) - 1) + 1)
    # print('w')
    # print(w)
    return SD_ISD(N, k, min(w, t))


def BJMM_ISD_lam(N, k, t, lam):
    w = int(t * pow(2, lam - 1) / (pow(2, lam) - 1) + 1)
    # print('w')
    # print(w)
    return BJMM_ISD(N, k, min(w, t))


#####################      Statistical decoding attack     ###########################

# The cost of statistical decoding attack over F_2
def SDfor2(N, k, t):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    pp = decimal.Decimal(N - t + 1) / decimal.Decimal(N - k - t)
    pp = pp.log10() / log10Two
    pp = pp * 2 * t

    #print("    SDfor2(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(np.log2(k + 1) + float(pp)))

    return np.log2(k + 1) + float(pp)


# The cost of statistical decoding attack over a larger field
def SDforq(N, k, t):
    decimal.getcontext().prec = 170
    log10Two = decimal.Decimal(2).log10()

    pp = com(N, t).log10() / log10Two - (com(N - k - 1, t).log10() / log10Two)

    #print("    SDforq(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str( np.log2(k + 1) + float(2 * pp)))
    return np.log2(k + 1) + float(2 * pp)



# The cost of statistical decoding 2.0 attack over F_2
def SD2for2(N, k, t):
    s = math.floor(Gauss(N, k, t))
    T = SDfor2(N, k-s, t)
    #print("   SD2for2(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(T))
    return T

def SD2forq(N, k, t,q):
    s = math.floor(Gauss(N, k, t)/math.log2(q))
    T = SDforq(N, k-s, t)
    #print("   SD2forq(N, k, t)   N = " + str(N) + "     k = " + str(k) + "    t = " + str(t) + "  cost  " + str(T))
    return T



#####################      The recent algebraic attack (AGB),  in EC23      ###########################
# The cost of AGB over F_q

def subsubAGBforq(n, k, h, f, mu):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    h = decimal.Decimal(h)
    f = decimal.Decimal(f)
    mu = decimal.Decimal(mu)
    beta = decimal.Decimal(math.floor(n / h))

    a1 = -(n - k - h)
    a2 = (n - k - h) * (n - k - h - 1) / 2
    a3 = -(n - k - h) * (n - k - h - 1) * (n - k - h - 2) / 6
    a4 = (n - k - h) * (n - k - h - 1) * (n - k - h - 2) * (n - k - h - 3) / 24

    b1 = (beta - mu - 1) * f
    b2 = (beta - mu - 1) ** 2 * f * (f - 1) / 2
    b3 = (beta - mu - 1) ** 3 * f * (f - 1) * (f - 2) / 6
    b4 = (beta - mu - 1) ** 4 * f * (f - 1) * (f - 2) * (f - 3) / 24

    c1 = (beta - 1) * (h - f)
    c2 = (beta - 1) ** 2 * (h - f) * (h - f - 1) / 2
    c3 = (beta - 1) ** 3 * (h - f) * (h - f - 1) * (h - f - 2) / 6
    c4 = (beta - 1) ** 4 * (h - f) * (h - f - 1) * (h - f - 2) * (h - f - 3) / 24

    d2 = a1 * b1 + a1 * c1 + b1 * c1 + a2 + b2 + c2
    d3 = c3 + b1 * c2 + b2 * c1 + b3 + a1 * (b1 * c1 + b2 + c2) + a2 * (b1 + c1) + a3
    d4 = c4 + b1 * c3 + b2 * c2 + b3 * c1 + b4 + a1 * (b1 * c2 + b2 * c1 + b3 + c3) + a2 * (b2 + c2 + b1 * c1) + a3 * (
            b1 + c1) + a4

    if d2 < 1:
        return 2

    if d3 < 1:
        return 3

    if d4 < 1:
        return 4

    return 0


def subAGBforq(n, k, h, f, mu):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    h = decimal.Decimal(h)
    f = decimal.Decimal(f)
    mu = decimal.Decimal(mu)
    beta = decimal.Decimal(math.floor(n / h))

    a1 = (beta - mu - 1) * f
    a2 = (beta - mu - 1) ** 2 * f * (f - 1) / 2
    a3 = (beta - mu - 1) ** 3 * f * (f - 1) * (f - 2) / 6
    a4 = (beta - mu - 1) ** 4 * f * (f - 1) * (f - 2) * (f - 3) / 24

    b1 = (beta - 1) * (h - f)
    b2 = (beta - 1) ** 2 * (h - f) * (h - f - 1) / 2
    b3 = (beta - 1) ** 3 * (h - f) * (h - f - 1) * (h - f - 2) / 6
    b4 = (beta - 1) ** 4 * (h - f) * (h - f - 1) * (h - f - 2) * (h - f - 3) / 24

    c1 = (h - 1)
    c2 = (h) * (h - 1) / 2
    c3 = (h + 1) * (h) * (h - 1) / 6
    c4 = (h + 2) * (h + 1) * (h) * (h - 1) / 24

    d = subsubAGBforq(n, k, h, f, mu)
    d2 = a1 + b1 + c1 + a1 * b1 + a1 * c1 + b1 * c1 + a2 + b2 + c2
    if d == 2:
        cost = d2

    elif d == 3:
        d3 = c3 + b1 * c2 + b2 * c1 + b3 + a1 * (b1 * c1 + b2 + c2) + a2 * (b1 + c1) + a3
        cost = d2 + d3

    elif d == 4:
        d3 = c3 + b1 * c2 + b2 * c1 + b3 + a1 * (b1 * c1 + b2 + c2) + a2 * (b1 + c1) + a3
        d4 = c4 + b1 * c3 + b2 * c2 + b3 * c1 + b4 + a1 * (b1 * c2 + b2 * c1 + b3 + c3) + a2 * (
                b2 + c2 + b1 * c1) + a3 * (b1 + c1) + a4
        cost = d2 + d3 + d4

    else:
        return 1000000
    return 2 * cost.log10() / log10Two + (3 * (k + 1 - f * mu)).log10() / log10Two - f * (
                1 - mu / beta).log10() / log10Two


def AGBforq(n, k, h):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    finalcost = 999999
    finalf = 99999
    finalmu = 999999
    for f in range(0, h):
        for mu in range(0, math.floor(n / h)):
            if f * mu < k + 1:
                subcost = subAGBforq(n, k, h, f, mu)
                if finalcost > subcost:
                    finalcost = subcost
                    finalf = f
                    finalmu = mu
    #print(subsubAGBforq(n, k, h, finalf, finalmu))
    #print(finalf)
    #print(finalmu)
    #print("   AGBforq(n, k, h) for larger field   n = " + str(n) + "     k = " + str(k) + "    h = " + str(h) + "  cost  " + str(round(finalcost,8)))
    return round(finalcost,2)


# The cost of AGB over F_2
def subsubAGBfor2(n, k, h, f, mu):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    h = decimal.Decimal(h)
    f = decimal.Decimal(f)
    mu = decimal.Decimal(mu)
    beta = decimal.Decimal(math.floor(n / h))
    a1 = (beta - mu - 1) * f
    a2 = (beta - mu - 1) ** 2 * f * (f - 1) / 2
    a3 = (beta - mu - 1) ** 3 * f * (f - 1) * (f - 2) / 6
    a4 = (beta - mu - 1) ** 4 * f * (f - 1) * (f - 2) * (f - 3) / 24

    b1 = (beta - 1) * (h - f)
    b2 = (beta - 1) ** 2 * (h - f) * (h - f - 1) / 2
    b3 = (beta - 1) ** 3 * (h - f) * (h - f - 1) * (h - f - 2) / 6
    b4 = (beta - 1) ** 4 * (h - f) * (h - f - 1) * (h - f - 2) * (h - f - 3) / 24

    c1 = -(n - k - 1)
    c2 = (n - k) * (n - k - 1) / 2
    c3 = -(n - k + 1) * (n - k) * (n - k - 1) / 6
    c4 = (n - k + 2) * (n - k + 1) * (n - k) * (n - k - 1) / 24

    d2 = a1 + b1 + c1 + a1 * b1 + a1 * c1 + b1 * c1 + a2 + b2 + c2
    d3 = c3 + b1 * c2 + b2 * c1 + b3 + a1 * (b1 * c1 + b2 + c2) + a2 * (b1 + c1) + a3
    d4 = c4 + b1 * c3 + b2 * c2 + b3 * c1 + b4 + a1 * (b1 * c2 + b2 * c1 + b3 + c3) + a2 * (b2 + c2 + b1 * c1) + a3 * (
            b1 + c1) + a4

    if d2 < 1:
        return 2

    if d3 < 1:
        return 3

    if d4 < 1:
        return 4

    return 0


def subAGBfor2(n, k, h, f, mu):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    h = decimal.Decimal(h)
    f = decimal.Decimal(f)
    mu = decimal.Decimal(mu)
    beta = decimal.Decimal(math.floor(n / h))


    a1 = (beta - mu - 1) * f
    a2 = (beta - mu - 1) ** 2 * f * (f - 1) / 2
    a3 = (beta - mu - 1) ** 3 * f * (f - 1) * (f - 2) / 6
    a4 = (beta - mu - 1) ** 4 * f * (f - 1) * (f - 2) * (f - 3) / 24

    b1 = (beta - 1) * (h - f)
    b2 = (beta - 1) ** 2 * (h - f) * (h - f - 1) / 2
    b3 = (beta - 1) ** 3 * (h - f) * (h - f - 1) * (h - f - 2) / 6
    b4 = (beta - 1) ** 4 * (h - f) * (h - f - 1) * (h - f - 2) * (h - f - 3) / 24

    d = subsubAGBfor2(n, k, h, f, mu)
    d2 = a1 + b1 + a1 * b1 + a2 + b2
    if d == 2:
        cost = d2

    elif d == 3:
        d3 = b3 + a1 * b2 + a2 * b1 + a3
        cost = d2 + d3

    elif d == 4:
        d3 = b3 + a1 * b2 + a2 * b1 + a3
        d4 = b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4
        cost = d2 + d3 + d4

    else:
        return 1000000

    return 2 * cost.log10() / log10Two + (3 * (k + 1 - f * mu)).log10() / log10Two - f * (
                1 - mu / beta).log10() / log10Two


def AGBfor2(n, k, h):
    n = decimal.Decimal(n)
    k = decimal.Decimal(k)
    finalcost = 999999
    finalf = 99999
    finalmu = 999999
    for f in range(0, h):
        for mu in range(0, math.floor(n / h)):
            if f * mu < k + 1:
                subcost = subAGBfor2(n, k, h, f, mu)
                if finalcost > subcost:
                    finalcost = subcost
                    finalf = f
                    finalmu = mu

    #print(subsubAGBfor2(n, k, h, finalf, finalmu))
    #print(finalf)
    #print(finalmu)
    #print("   AGBfor2(n, k, h) for F2  n = " + str(n) + "     k = " + str(k) + "    h = " + str(h) + "  cost  " + str(round(finalcost,8)))

    return round(finalcost,2)


#####################      Bit security of LPN and dual LPN     ###########################
"""
We propose a non-asymptotic cost of the information set decoding algorithm, Pooled Gauss attack, and statistical decoding attack
against the LPN problem over finite fields F_q or a ring Z_{2^lambda} with parameters

LPN parameters: N (number of queries), 
                k (length of secret), 
                t (Hamming weight of noise), 
                q (size of field) and 
                lambda (bit size of ring)

dual LPN parameters：n (corresponding to the number of COT/VOLE correlations), 
                     N (number of queries), 
                     t (Hamming weight of noise), 
                     q (size of field) and 
                     lambda (bit size of ring)

noise parameters: exact or regular. The default functions listed below apply to exact noise, unless the function name  101122131232  is specifically labeled as "regular."
"""


def analysisfor2(N, k, t):
    T1 = Gauss(N, k, t)
    T2 = SDfor2(N, k, t)
    T3 = SD2for2(N, k, t)
    T4 = SD_ISD(N, k, t)
    T5 = BJMM_ISD(N, k, t)


    min = T1
    if min > T2:
        min = T2

    if min > T3:
        min = T3

    if min > T4:
        min = T4

    if min > T5:
        min = T5

    return min

def analysisfor2regular(N, k, t):
    T1 = AGBfor2(N, k, t)

    N = N - t
    k = k - t
    T2 = analysisfor2(N, k, t)



    min = T1
    if min > T2:
        min = T2

    return min



def analysisfordual2(n, N, t):
    k = N - n
    min = analysisfor2(N, k, t)

    return min


def analysisfordual2regular(n, N, t):
    k = N - n

    min = analysisfor2regular(N, k, t)

    return min


def analysisforq(N, k, t, q):
    T1 = SD_ISD_q(N, k, t, q)
    T2 = SDforq(N, k, t)
    T3 = Gauss(N, k, t)
    T4 = SD2forq(N, k, t, q)

    min = T1
    if min > T2:
        min = T2

    if min > T3:
        min = T3

    if min > T4:
        min = T4

    return min


def analysisforqregular(N, k, t, q):
    T1 = AGBforq(N, k, t)

    #N = N - t
    #k = k - t
    T2 = analysisforq(N, k, t, q)

    min = T1
    if min > T2:
        min = T2

    return min


def analysisfordualq(n, N, t, q):
    k = N - n
    min = analysisforq(N, k, t, q)

    return min


def analysisfordualqregular(n, N, t, q):
    k = N - n
    return analysisforqregular(N, k, t, q)


def analysisfor2lambda(N, k, t, lam):
    t = min(t, int(t * pow(2, lam - 1) / (pow(2, lam) - 1) + 1))



    return analysisfor2(N, k, t)


def analysisfor2lambdaregular(N, k, t, lam):

    return analysisfor2lambda(N, k, t, lam)


def analysisfordual2lambda(n, N, t, lam):
    k = N - n

    min = analysisfor2lambda(N, k, t, lam)

    return min



def analysisfordual2lambdaregular(n, N, t, lam):
    k = N - n

    min = analysisfordual2lambda(n, N, t, lam)

    return min


#####################      main() function   ###########################

def main():

    #print(len(sys.argv))
    if len(sys.argv) < 4 or len(sys.argv) > 6:
        print(" ============================================input error ================================================  ")
        print("input format of exact LPN:  N=1024 k=652 t=57 exact ")
        print(" ============================================================================================  ")
        print("or  N=1024 k=652 t=57 lambda=12 exact  #(bit security of exact LPN with ring size 2^lambda) ")
        print("or  N=1024 k=652 t=57 q=12 exact #(bit security of exact LPN with field size q ")
        print("or  n=1024 N=4096 t=88 exact #(bit security of dual exact LPN) ")
        print("or  n=1024 N=4096 t=88 lambda=12 exact #(bit security of dual exact LPN with ring size 2^lambda) ")
        print("or  n=1024 N=4096 t=88 q=12 exact #(bit security of dual exact LPN with field size q ")
        print(" ============================================================================================  ")
        print("input format of regular LPN:  N=1024 k=652 t=57 regular ")
        print("or  N=1024 k=652 t=57 lambda=12 regular #(bit security of regular LPN with ring size 2^lambda) ")
        print("or  N=1024 k=652 t=57 q=12 regular #(bit security of regular LPN with field size q ")
        print("or  n=1024 N=4096 t=88 regular #(bit security of dual regular LPN) ")
        print("or  n=1024 N=4096 t=88 lambda=12 regular #(bit security of dual regular LPN with ring size 2^lambda) ")
        print("or  n=1024 N=4096 t=88 q=12 regular #(bit security of dual regular LPN with field size q ")


    elif 'n' in sys.argv[1] and 'N' in sys.argv[2] and 't' in sys.argv[3]:
        n = int(re.findall(r"\d+", sys.argv[1]).pop())
        N = int(re.findall(r"\d+", sys.argv[2]).pop())
        t = int(re.findall(r"\d+", sys.argv[3]).pop())

        if len(sys.argv) == 5 and 'e' in sys.argv[-1]:
            print("bit security of dual exact LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + "):")
            print(analysisfordual2(n, N, t))
            print()

        elif len(sys.argv) == 5 and 'r' in sys.argv[-1]:
            print("bit security of dual regular LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + "):")
            print(analysisfordual2regular(n, N, t))
            print()

        elif 'q' in sys.argv[-2] and 'e' in sys.argv[-1]:
            q = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of dual exact LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + ", q=" + str(q) + "):")
            print(analysisfordualq(n, N, t, q))
            print()

        elif 'q' in sys.argv[-2] and 'r' in sys.argv[-1]:
            q = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of regular LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + ", q=" + str(q) + "):")
            print(analysisfordualqregular(n, N, t, q))
            print()


        elif 'lambda' in sys.argv[-2] and 'e' in sys.argv[-1]:
            lam = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of dual exact LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + ", lambda=" + str(
                lam) + "):")
            print(analysisfordual2lambda(n, N, t, lam))
            print()

        elif 'lambda' in sys.argv[-2] and 'r' in sys.argv[-1]:
            lam = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of dual regular LPN (n=" + str(n) + ", N=" + str(N) + ", t=" + str(t) + ", lambda=" + str(
                lam) + "):")
            print(analysisfordual2lambdaregular(n, N, t, lam))
            print()

        else:
            print(" ============================================input error ================================================  ")
            print("input format of exact LPN:  N=1024 k=652 t=57 exact ")
            print(" ============================================================================================  ")
            print("or  N=1024 k=652 t=57 lambda=12 exact  #(bit security of exact LPN with ring size 2^lambda) ")
            print("or  N=1024 k=652 t=57 q=12 exact #(bit security of exact LPN with field size q ")
            print("or  n=1024 N=4096 t=88 exact #(bit security of dual exact LPN) ")
            print("or  n=1024 N=4096 t=88 lambda=12 exact #(bit security of dual exact LPN with ring size 2^lambda) ")
            print("or  n=1024 N=4096 t=88 q=12 exact #(bit security of dual exact LPN with field size q ")
            print(" ============================================================================================  ")
            print("input format of regular LPN:  N=1024 k=652 t=57 regular ")
            print("or  N=1024 k=652 t=57 lambda=12 regular #(bit security of regular LPN with ring size 2^lambda) ")
            print("or  N=1024 k=652 t=57 q=12 regular #(bit security of regular LPN with field size q ")
            print("or  n=1024 N=4096 t=88 regular #(bit security of dual regular LPN) ")
            print("or  n=1024 N=4096 t=88 lambda=12 regular #(bit security of dual regular LPN with ring size 2^lambda) ")
            print("or  n=1024 N=4096 t=88 q=12 regular #(bit security of dual regular LPN with field size q ")


    elif 'N' in sys.argv[1] and 'k' in sys.argv[2] and 't' in sys.argv[3]:
        N = int(re.findall(r"\d+", sys.argv[1]).pop())
        k = int(re.findall(r"\d+", sys.argv[2]).pop())
        t = int(re.findall(r"\d+", sys.argv[3]).pop())

        if len(sys.argv) == 5 and 'e' in sys.argv[-1]:
            print("bit security of exact LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + "):")
            print(analysisfor2(N, k, t))
            print()

        elif len(sys.argv) == 5 and 'r' in sys.argv[-1]:
            print("bit security of regular LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + "):")
            print(analysisfor2regular(N, k, t))
            print()

        elif 'q' in sys.argv[-2] and 'e' in sys.argv[-1]:
            q = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + ", q=" + str(
                q) + "):")
            print(analysisforq(N, k, t, q))


        elif 'q' in sys.argv[-2] and 'r' in sys.argv[-1]:
            q = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of regular LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + ", q=" + str(
                q) + "):")
            print(analysisforqregular(N, k, t, q))

        elif 'lambda' in sys.argv[-2] and 'e' in sys.argv[-1]:
            lam = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of exact LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + ", lambda=" + str(
                lam) + "):")
            print(analysisfor2lambda(N, k, t, lam))



        elif 'lambda' in sys.argv[-1] and 'r' in sys.argv[4]:
            lam = int(re.findall(r"\d+", sys.argv[4]).pop())
            print("bit security of regular LPN (N=" + str(N) + ", k=" + str(k) + ", t=" + str(t) + ", lambda=" + str(
                lam) + "):")
            print(analysisfor2lambdaregular(N, k, t, lam))

        else:
            print(" ============================================input error ================================================  ")
            print("input format of exact LPN:  N=1024 k=652 t=57 exact ")
            print(" ============================================================================================  ")
            print("or  N=1024 k=652 t=57 lambda=12 exact  #(bit security of exact LPN with ring size 2^lambda) ")
            print("or  N=1024 k=652 t=57 q=12 exact #(bit security of exact LPN with field size q ")
            print("or  n=1024 N=4096 t=88 exact #(bit security of dual exact LPN) ")
            print("or  n=1024 N=4096 t=88 lambda=12 exact #(bit security of dual exact LPN with ring size 2^lambda) ")
            print("or  n=1024 N=4096 t=88 q=12 exact #(bit security of dual exact LPN with field size q ")
            print(" ============================================================================================  ")
            print("input format of regular LPN:  N=1024 k=652 t=57 regular ")
            print("or  N=1024 k=652 t=57 lambda=12 regular #(bit security of regular LPN with ring size 2^lambda) ")
            print("or  N=1024 k=652 t=57 q=12 regular #(bit security of regular LPN with field size q ")
            print("or  n=1024 N=4096 t=88 regular #(bit security of dual regular LPN) ")
            print("or  n=1024 N=4096 t=88 lambda=12 regular #(bit security of dual regular LPN with ring size 2^lambda) ")
            print("or  n=1024 N=4096 t=88 q=12 regular #(bit security of dual regular LPN with field size q ")
            
            
    else:
        print(" ============================================input error ================================================  ")
        print("input format of exact LPN:  N=1024 k=652 t=57 exact ")
        print(" ============================================================================================  ")
        print("or  N=1024 k=652 t=57 lambda=12 exact  #(bit security of exact LPN with ring size 2^lambda) ")
        print("or  N=1024 k=652 t=57 q=12 exact #(bit security of exact LPN with field size q ")
        print("or  n=1024 N=4096 t=88 exact #(bit security of dual exact LPN) ")
        print("or  n=1024 N=4096 t=88 lambda=12 exact #(bit security of dual exact LPN with ring size 2^lambda) ")
        print("or  n=1024 N=4096 t=88 q=12 exact #(bit security of dual exact LPN with field size q ")
        print(" ============================================================================================  ")
        print("input format of regular LPN:  N=1024 k=652 t=57 regular ")
        print("or  N=1024 k=652 t=57 lambda=12 regular #(bit security of regular LPN with ring size 2^lambda) ")
        print("or  N=1024 k=652 t=57 q=12 regular #(bit security of regular LPN with field size q ")
        print("or  n=1024 N=4096 t=88 regular #(bit security of dual regular LPN) ")
        print("or  n=1024 N=4096 t=88 lambda=12 regular #(bit security of dual regular LPN with ring size 2^lambda) ")
        print("or  n=1024 N=4096 t=88 q=12 regular #(bit security of dual regular LPN with field size q ")


##################################
# Executed code
##################################
if __name__ == '__main__':
    main()

