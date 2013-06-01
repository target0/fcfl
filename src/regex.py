#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys
from time import time

debug = False

"""
This file contains all the algorithms and classes necessary to the
transformation and processing of a regular path expression into
a deterministic finite automaton
"""

# Some helper functions
def dlog(s):
    if debug:
        print s

def is_states_in_list(slist, states):
    for s in slist:
        if len(s) != len(states):
            continue
        eq = True
        for i in range(len(s)):
            if s[i] != states[i]:
                eq = False
                break
        if eq:
            return True

    return False

def get_index_in_list(slist, states):
    for i in range(len(slist)):
        s = slist[i]
        if len(s) != len(states):
            continue
        eq = True
        for j in range(len(s)):
            if s[j] != states[j]:
                eq = False
                break
        if eq:
            return i

    return None

class FSM:
    """
    Finite State Machine class. It represents a NFA or a DFA.
    """

    # some constants
    epsilon = -1
    dot = -3

    def __init__(self):
        self.states = {}    # state -> {input -> [states]}
        self.accepting = [] # accepting states
        self.dfa = False    # False = NFA, True = DFA
        self.last_state = None

    def state_size(self):
        return len(self.states.keys())

    def add_transition(self, state, symbol, next_state):
        """ Add a transition from @state to @next_state with @symbol """
        if state not in self.states:
            self.states[state] = {}
        if symbol not in self.states[state]:
            self.states[state][symbol] = []
        self.states[state][symbol].append(next_state)

        if next_state not in self.states:
            self.states[next_state] = {}

        # Dot character fix
        if symbol == FSM.dot: # override existing next state
            for tsym in self.states[state].keys():
                if tsym == FSM.dot:
                    continue
                if next_state in self.states[state][tsym]:
                    self.states[state][tsym].remove(next_state)
                    dlog('Removing transition '+str(state)+' -- '+str(tsym)+' --> '+str(next_state)+' overriden by dot')
                    if len(self.states[state][tsym]) == 0:
                        del self.states[state][tsym]

    def set_accepting(self, states):
        for q in states:
            if q not in self.accepting:
                self.accepting.append(q)

    def get_transitions(self, states):
        ret = []

        for q in states:
            for sym in self.states[q]:
                if sym not in ret:
                    ret.append(sym)

        return ret

    def get_next_states(self, states, symbol):
        def uniq(i):
            o = []
            for x in i:
                if x not in o:
                    o.append(x)
            return o

        ret = []
        for q in states:
            if symbol in self.states[q]:
                if len(self.states[q][symbol]) > 0:
                    ret.extend(self.states[q][symbol])

        return uniq(sorted(ret))

    def get_all_transitions(self):
        ret = []

        for q in self.states:
            for sym in self.states[q]:
                for t in self.states[q][sym]:
                    ret.append((q,sym,t))

        return ret

    def reset_transitions(self, E):
        self.states = {}

        for q, sym, t in E:
            self.add_transition(q, sym, t)

    def import_transitions(self, E, offset):
        for q, sym, t in E:
            self.add_transition(q+offset, sym, t+offset)

    def remove_epsilon(self):
        """
        Implementation of the epsilon-removal by loop reduction algorithm
        """
        E = self.get_all_transitions()
        F = self.accepting
        queue = []

        for q, sym, t in E:
            if sym is FSM.epsilon:
                queue.append((q, t))

        dlog(len(queue))
        iteration = 0

        while len(queue) > 0:
            iteration += 1
            if iteration % 1000 == 0:
                dlog(str(iteration)+' (qlen '+str(len(queue))+')') # count iterations for debugging purposes
            p, qm = queue.pop(0)
            dlog('Initially removing ('+str(p)+', epsilon) -> '+str(qm))
            E.pop(E.index((p, FSM.epsilon, qm)))

            if p == qm:
                E[:] = [(qq, ssym, tt) for (qq, ssym, tt) in E if qq == p]
            else:
                tmpE = []
                for tmpqm, a, qn in E:
                    if tmpqm != qm:
                        continue
                    dlog('Adding connection ('+str(p)+', '+str(a)+') -> '+str(qn))
                    tmpE.append((p, a, qn))
                    if a is FSM.epsilon:
                        queue.append((p, qn))
                E.extend(tmpE)

                if qm in F and p not in F:
                    F.append(p)

        dlog('New transitions')
        dlog(E)
        dlog('New accepting')
        dlog(F)
        self.reset_transitions(E)
        self.accepting = F

    def to_dfa(self):
        """
        Transform to DFA with Rabin-Scott subset contruction algorithm
        """
        if self.dfa == True:
            return self

        Q = [ [ 0 ] ]
        Q2 = [ [ 0 ] ]
        F2 = []

        while len(Q) > 0:
            q2 = Q.pop()
            for q in q2:
                if q in self.accepting:
                    F2.append(q2)
                    break
            syms = self.get_transitions(q2)
            for sym in syms:
                ns = self.get_next_states(q2, sym)
                if not is_states_in_list(Q2, ns):
                    Q2.append(ns)
                    Q.append(ns)

        m2 = FSM()
        for i in range(len(Q2)):
            syms = self.get_transitions(Q2[i])
            for sym in syms:
                ns = self.get_next_states(Q2[i], sym)
                idx = get_index_in_list(Q2, ns)
                m2.add_transition(i, sym, idx)
                dlog('Mapping ('+str(i)+', '+str(sym)+') -> '+str(idx)+' from original ('+(str(Q2[i]))+', '+str(sym)+') -> '+str(ns))

        for s in F2:
            idx = get_index_in_list(Q2, s)
            m2.set_accepting([idx])

        m2.dfa = True
        return m2

    def process(self, data):
        """
        Process an input string and return the accepting state, or None if
        no accepting state was reached or there was an error
        """

        if not self.dfa:
            dlog('Please transform to DFA first')
            return None

        curstate = 0
        for sym in data:
            syms = self.get_transitions([curstate])
            if sym not in syms and FSM.dot not in syms:
                dlog('No transition available at state %d, input not accepted, aborting' % (curstate))
                return None
            if sym not in syms and FSM.dot in syms:
                sym = FSM.dot
            nstate = self.get_next_states([curstate], sym)
            if len(nstate) == 0:
                dlog('Transition exists but next state is unavailable, this should never happen, aborting')
                return None
            if len(nstate) > 1:
                dlog('Automaton is supposedly DFA but multiple transitions available for state %d, aborting' % (curstate))
                return None

            curstate = nstate[0]

        # Return None if input is not accepted
        if curstate not in self.accepting:
            dlog('Input consumed but final state %d is not accepting, failed to accept input' % (curstate))
            return None

        return curstate

class AST:
    def __init__(self):
        self.left = None
        self.right = None
        self.data = None

    def __init__(self, l, r, d):
        self.left = l
        self.right = r
        self.data = d

class RegexParser:
    """
    Main parser class for the regular path expressions
    """

    # Some constants
    KLEENE = -2
    WILDCARD = -3
    UNION = -4
    CONCAT = -5

    def __init__(self):
        pass

    def get_fsm_symbol(self, sym):
        """ Single symbol to FSM """
        fsm = FSM()
        fsm.add_transition(0, sym, 1)
        fsm.set_accepting([1])
        fsm.last_state = 1
        return fsm

    def get_fsm_union(self, m1, m2):
        """ Merge two FSM with union operator """
        fsm = FSM()
        m1_init = 1
        m2_init = 1+m1.state_size()
        fstate = m2_init+m2.state_size()

        fsm.import_transitions(m1.get_all_transitions(), m1_init)
        fsm.import_transitions(m2.get_all_transitions(), m2_init)
        fsm.add_transition(0, FSM.epsilon, m1_init)
        fsm.add_transition(0, FSM.epsilon, m2_init)
        fsm.add_transition(m1.last_state+m1_init, FSM.epsilon, fstate)
        fsm.add_transition(m2.last_state+m2_init, FSM.epsilon, fstate)
        fsm.set_accepting([fstate])
        fsm.last_state = fstate
        return fsm

    def get_fsm_concat(self, m1, m2):
        """ Merge two FSM with (implicit) concatenation operator """
        fsm = FSM()
        m2_offset = m1.state_size() - 1
        fstate = m2.last_state + m2_offset

        fsm.import_transitions(m1.get_all_transitions(), 0)
        fsm.import_transitions(m2.get_all_transitions(), m2_offset)
        fsm.set_accepting([fstate])
        fsm.last_state = fstate
        return fsm

    def get_fsm_kleene(self, m1):
        """ Apply the Kleene operator to an FSM """
        fsm = FSM()
        m1_offset = 1
        fstate = m1_offset + m1.state_size()

        fsm.import_transitions(m1.get_all_transitions(), m1_offset)
        fsm.add_transition(0, FSM.epsilon, 1)
        fsm.add_transition(0, FSM.epsilon, fstate)
        fsm.add_transition(m1.last_state+m1_offset, FSM.epsilon, 1)
        fsm.add_transition(m1.last_state+m1_offset, FSM.epsilon, fstate)
        fsm.set_accepting([fstate])
        fsm.last_state = fstate
        return fsm

    def translate_ast(self, ast):
        """ Generate corresponding FSM from AST data """
        if ast.data == RegexParser.KLEENE:
            return self.get_fsm_kleene(self.translate_ast(ast.left))
        elif ast.data == RegexParser.CONCAT:
            return self.get_fsm_concat(self.translate_ast(ast.left), self.translate_ast(ast.right))
        elif ast.data == RegexParser.UNION:
            return self.get_fsm_union(self.translate_ast(ast.left), self.translate_ast(ast.right))
        else:
            return self.get_fsm_symbol(ast.data)

    def get_next_symbol(self, s):
        """ Get next symbol in input string. Returns symbol,isoperator tuple.
            @symbol is an internal representation of the symbol
            @isoperator is True if the parsed sym is an operator, False otherwise
        """
        if len(s) == 0:
            return None, None

        # Dot character, Kleene star or union operator
        if s[0] == '.' or s[0] == '*' or s[0] == '|':
            if s[0] == '.':
                sym = RegexParser.WILDCARD
                s[:] = s[1:]
                return sym, False
            elif s[0] == '*':
                sym = RegexParser.KLEENE
            elif s[0] == '|':
                sym = RegexParser.UNION
            s[:] = s[1:]
            return sym, True
        # Switch symbol
        elif s[0] == 's':
            sym = 's'
            s[:] = s[1:]
            while len(s) > 0 and s[0] in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
                sym += s[0]
                s[:] = s[1:]
            return sym, False
        # Concatenation operator
        elif s[0] == ',':
            s[:] = s[1:]
            return RegexParser.CONCAT, True

        dlog('Failed for '+str.join('',s))
        return None

    def concat(self, array, root):
        if len(array) == 0:
            return root
        return self.concat(array[1:], AST(root, array[0], RegexParser.CONCAT))

    def parse(self, regex):
        """ Generate an AST from a path expression """

        farray = []
        union = False
        psym = False
        ast = None

        while len(regex) > 0:
            sym, isop = self.get_next_symbol(regex)
            dlog('Parsing sym '+str(sym)+' and isop '+str(isop))
            if not isop:
                if psym:
                    union = False
                if union:
                    ast.right = AST(None, None, sym)
                    dlog('Setting right child of ast to symbol')
                else:
                    if ast is not None:
                        farray.append(ast)
                        dlog('Appending ast')
                    union = False
                    ast = AST(None, None, sym)
                    dlog('Created blank ast with symbol')
                psym = True
            else:
                if sym == RegexParser.CONCAT:
                    continue
                if sym == RegexParser.UNION:
                    union = True
                elif union:
                    union = False
                ast = AST(ast, None, sym)
                psym = False
                if debug:
                    dlog('Created blank ast with previous ast and symbol')
        farray.append(ast)

        if len(farray) > 1:
            res = self.concat(farray[1:], farray[0])
        else:
            res = farray[0]

        return res

    def create_fsm(self, regex):
        # Transform input string to list
        rlist = [x for x in regex]

        # Generate AST from input
        ast = self.parse(rlist)

        # Translate AST to NFA
        fsm = self.translate_ast(ast)
        dlog('NFA FULL TRANSITIONS:')
        dlog(str(fsm.get_all_transitions()))
        dlog('ACCEPTING')
        dlog(str(fsm.accepting))
        dlog('EOF')

        # Apply epsilon-removal algorithm
        fsm.remove_epsilon()

        # Translate NFA to DFA
        dfa = fsm.to_dfa()

        return dfa
