// Minimal executable adapter around the pinned official cardenc headers.
//
// This file contains no encoding logic.  It exposes card.hh::_encode_atmost
// and _encode_atleast so the independent Python transcription can be compared
// directly with the upstream C++ implementation.

#include <cstdlib>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "card.hh"

int main(int argc, char **argv)
{
    if (argc != 6) {
        std::cerr << "usage: source_reference_driver "
                  << "atmost|atleast ARITY BOUND TOP SIGN\n";
        return 2;
    }

    const std::string operation(argv[1]);
    const int arity = std::atoi(argv[2]);
    const int bound = std::atoi(argv[3]);
    int top = std::atoi(argv[4]);
    const int sign = std::atoi(argv[5]);
    if (arity <= 0 || top < arity || (sign != 1 && sign != -1)) {
        std::cerr << "invalid numeric argument\n";
        return 2;
    }

    std::vector<int> inputs;
    for (int variable = 1; variable <= arity; ++variable)
        inputs.push_back(sign * variable);

    ClauseSet clauses;
    if (operation == "atmost")
        _encode_atmost(clauses, inputs, bound, top, enc_kmtot);
    else if (operation == "atleast")
        _encode_atleast(clauses, inputs, bound, top, enc_kmtot);
    else {
        std::cerr << "unknown operation\n";
        return 2;
    }

    std::cout << "p " << top << " " << clauses.size() << "\n";
    for (std::vector<std::vector<int> >::const_iterator clause =
             clauses.get_clauses().begin();
         clause != clauses.get_clauses().end(); ++clause) {
        for (std::vector<int>::const_iterator literal = clause->begin();
             literal != clause->end(); ++literal)
            std::cout << *literal << " ";
        std::cout << "0\n";
    }
    return 0;
}
