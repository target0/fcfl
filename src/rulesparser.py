#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys, re
from collections import Counter
import constraints.manager as cmanager

class Requirements:
    """
    Store parsed constraints
    """
    def __init__(self):
        self.atoms = {}
        self.sets = {}
        self.aliases = {}
        self.constraints = []
        self.grpconstraints = {}
        self.conditions = []

    def add_constraint(self, c):
        self.constraints.append(c)

    def add_group_constraint(self, c, grpid):
        if grpid not in self.grpconstraints:
            grp = GroupConstraint(grpid)
            grp.constraints.append(c)
            self.grpconstraints[grpid] = grp
        else:
            grp = self.grpconstraints[grpid]
            grp.constraints.append(c)

    def add_condition(self, gc, constr):
        if gc not in self.conditions:
            gc.constr.append(constr)
            self.conditions.append(gc)
        else:
            idx = self.conditions.index(gc)
            self.conditions[idx].constr.append(constr)

    def finalize(self):
        """
        * Append each member of a constraint group to the list of constraints
        * Create the grouped conditions
        """

        for gid in self.grpconstraints:
            self.constraints.append(self.grpconstraints[gid])

        for constr in self.constraints:
            if constr.ctype == Constraint.CONSTR_GROUP:
                for subc in constr.constraints:
                    gc = GroupCondition(subc.conditions)
                    self.add_condition(gc, subc)
            else:
                gc = GroupCondition(constr.conditions)
                self.add_condition(gc, constr)

    def add_atom(self, atom, target):
        if atom not in self.atoms:
            self.atoms[atom] = [target]
        else:
            self.atoms[atom].append(target)

    def add_alias(self, var, target):
        self.aliases[var] = target

    def add_set(self, var, tdata):
        self.sets[var] = tdata

    def dump(self):
        print '--- ATOMS ---'
        for a in self.atoms:
            print str(a)+' -> '+str(self.atoms[a])

        print '\n--- SETS ---'
        for a in self.sets:
            print str(a)+' -> '+str(self.sets[a])

        print '\n--- ALIASES ---'
        for a in self.aliases:
            print str(a)+' -> '+str(self.aliases[a])

        print '\n--- CONSTRAINTS ---'
        i = 1
        for a in self.constraints:
            print '** Constraint '+str(i)
            a.dump()
            i += 1

    def host_to_node(self, h):
        if h[0] != 'h':
            return None
        return int(h[1:])

class Condition:
    """ Represent a single condition """

    COND_EQUAL = 1
    COND_ATOM = 2

    def __init__(self, ctype=None, source=None, target=None):
        self.ctype = ctype
        self.source = source #comparison variable, e.g. Hs or Ht
        self.target = target #target, e.g. lan() or Server_VoIP

    def __str__(self):
        if self.ctype == Condition.COND_EQUAL:
            return self.source+' = '+self.target
        elif self.ctype == Condition.COND_ATOM:
            return self.target+'('+self.source+')'

    def __hash__(self):
        return hash(str(self.ctype)+self.source+self.target)

    def __eq__(self, other):
        return self.ctype == other.ctype and self.source == other.source and self.target == other.target

class GroupCondition:
    """ Represent a group of conditions """

    INTERNALID = 1

    def __init__(self, conds=[]):
        self.conds = conds
        self.constr = []
        self.iid = GroupCondition.INTERNALID
        GroupCondition.INTERNALID += 1

    def __hash__(self):
        return hash(str(self.iid))

    def __eq__(self, other):
        return self.iid == other.iid

class Constraint(object):
    """ Abstract class for constraints """

    CONSTR_GROUP = -1

    def __init__(self, ctype):
        self.ctype = ctype
        self.verified = False

    def dump(self):
        print 'Generic dump.'

class SingleConstraint(Constraint):
    """ Represents a constraint """

    INTERNALID = 1

    def __init__(self, ctype, conds=None, data=None, grp=0, prio=0):
        super(SingleConstraint, self).__init__(ctype)
        self.conditions = conds     # List of conditions applied to the constraint
        self.prio = prio            # Priority level (0 if N/A)
        self.grp = grp              # Group label (0 if N/A)
        self.data = data            # Constraint data (returned by the constraint handler)
        self.verifrate = 0          # Match ratio, set by the constraint handler
        self.srate = 1              # Minimum success rate (aka weight for path cstr)
        self.iid = SingleConstraint.INTERNALID
        SingleConstraint.INTERNALID += 1

    def check(self):
        return float(self.verifrate) >= float(self.srate)

    def dump(self):
        print 'Prio: '+str(self.prio)
        print 'Data: '+str(self.data)
        print 'Conditions:'
        for c in self.conditions:
            print str(c)

    def __str__(self):
        s = ''
        if self.grp != 0:
            s += ':'+str(self.grp)+':'+str(self.prio)+':'

        inst = cmanager.getinstance(id=self.ctype)
        s += inst.kw+'('+inst.tostring(self.data)+')'

        if len(self.conditions) > 0:
            s += ' <= '+(" ^ ".join([str(x) for x in self.conditions]))

        return s

class GroupConstraint(Constraint):
    """ Constraint group """

    def __init__(self, group):
        super(GroupConstraint, self).__init__(Constraint.CONSTR_GROUP)
        self.group = group      # ID
        self.constraints = []   # list of constraints

    def dump(self):
        print 'GroupID: '+str(self.group)
        for c in self.constraints:
            print 'Dumping inner constraint'
            c.dump()

class RulesParser:
    """ Main parser """

    def __init__(self):
        pass

    def parse_conditions(self, conds):
        cds = []

        conds2 = re.sub(' ', '', conds)
        cdarray = conds2.split('^')
        for cond in cdarray:
            # Handle atom()
            r = re.search('^(.*)\((.*)\)$', cond)
            if r is not None:
                c = Condition(Condition.COND_ATOM, r.group(2), r.group(1))
                cds.append(c)
                continue
            # Handle S=T
            r = re.search('^(.*)=(.*)$', cond)
            if r is not None:
                c = Condition(Condition.COND_EQUAL, r.group(1), r.group(2))
                cds.append(c)
                continue
            sys.stderr.write('parse_conditions(): Unknown condition '+str(cond)+'\n')

        return cds

    def parse(self, fname):
        """ Actually parse the constraints file """
        req = Requirements()

        f = open(fname, 'r')
        data = f.readlines()
        f.close()

        for line in data:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue

            # Handle atom(X)
            r = re.search('^([A-Za-z0-9_]+)\(([A-Za-z0-9_]+)\)$', line)
            if r is not None:
                atom = r.group(1)
                target = r.group(2)
                if target in req.sets:
                    for a in req.sets[target]:
                        req.add_atom(atom, a)
                else:
                    req.add_atom(atom, target)
                continue

            # Handle var = X
            r = re.search('^([A-Za-z0-9_]+) = ([A-Za-z0-9_]+)$', line)
            if r is not None:
                var = r.group(1)
                target = r.group(2)
                req.add_alias(var, target)
                continue

            # Handle var = { set }
            r = re.search('^([A-Za-z0-9_]+) = {(.*)}$', line)
            if r is not None:
                var = r.group(1)
                tset = r.group(2)
                tset = re.sub(' ', '', tset)
                tdata = tset.split(',')
                req.add_set(var, tdata)
                continue

            grpid = 0
            prio = 0

            # Handle groups (:label:prio:kw)
            r = re.search('^:([0-9]+):([0-9]+):(.*)$', line)
            if r is not None:
                grpid = r.group(1)
                prio = int(r.group(2))
                line = r.group(3)

            # Handle keyword, arguments and conditions
            r = re.search('^([a-zA_Z0-9_]+)\((.*)\) <= (.*)$', line)
            if r is not None:
                keyword = r.group(1)
                args = r.group(2)
                conds = r.group(3)
                cds = self.parse_conditions(conds)

                inst = cmanager.getinstance(kw=keyword) # Get constraint handler
                data = inst.parse(args)

                constr = SingleConstraint(inst.iid, cds, data, grpid, prio)
                if 'srate' in data:
                    constr.srate = data['srate']

                if grpid == 0:
                    req.add_constraint(constr)
                else:
                    req.add_group_constraint(constr, grpid)

                continue

            sys.stderr.write('parse(): Unknown line '+line+'\n')

        req.finalize()
        return req

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print 'Usage: '+sys.argv[0]+' <rules file>'
        sys.exit(-1)

    p = RulesParser()
    req = p.parse(sys.argv[1])
    req.dump()

    print '------'
    print 'There are %d different conditions' % (len(req.conditions))

    for cond in req.conditions:
        print str(cond)
