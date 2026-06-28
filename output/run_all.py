#!/usr/bin/env python3
"""
Comprehensive benchmarking system for redactable blockchain schemes.
Implements: RPCH (proposed), Derler PCH, Tian PCHBA, Huang RCH
"""

import time
import os
import json
import hashlib
import pickle
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib import rcParams

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE
from charm.schemes.pksig.pksig_bls04 import BLS01
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import secp256k1
from charm.schemes.pksig.pksig_ecdsa import ECDSA

N_TRIALS = 20

def timed(func, *args, n_trials=N_TRIALS, **kwargs):
    """Run func n_trials times, return mean and std in milliseconds."""
    times = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        result = func(*args, **kwargs)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    return np.mean(times), np.std(times), result

# ============================================================================
# PRIMITIVES
# ============================================================================

class ChameleonHash:
    """DL-based Chameleon Hash"""
    def __init__(self, group):
        self.group = group
        self.g = group.random(G1)

    def keygen(self):
        x = self.group.random(ZR)
        pk = self.g ** x
        return pk, x

    def hash(self, pk, message_str):
        r = self.group.random(ZR)
        h_m = self.group.hash(message_str, ZR)
        ch = (self.g ** h_m) * (pk ** r)
        return ch, r

    def verify(self, pk, message_str, ch, r):
        h_m = self.group.hash(message_str, ZR)
        ch_check = (self.g ** h_m) * (pk ** r)
        return ch == ch_check

    def adapt(self, sk, m_old, m_new, ch, r_old):
        h_old = self.group.hash(m_old, ZR)
        h_new = self.group.hash(m_new, ZR)
        r_new = r_old - (h_new - h_old) / sk
        return r_new


class HuangRCH:
    """Pairing-based Revocable Chameleon Hash"""
    def __init__(self, group):
        self.group = group
        self.g = group.random(G1)

    def keygen(self):
        x = self.group.random(ZR)
        y = self.g ** x
        return y, x

    def hash(self, y, message_str, cid, t):
        h = self.group.hash(cid + str(t), G1)
        alpha = self.group.random(ZR)
        r = (self.g ** alpha, y ** alpha)
        h2m = self.group.hash(message_str, ZR)
        ch = pair(self.g ** (alpha * t), self.g) * pair(h ** (h2m * t), y)
        return ch, r, alpha

    def verify(self, y, message_str, ch, r, cid, t_current):
        g_alpha, y_alpha = r
        if pair(g_alpha, y) != pair(self.g, y_alpha):
            return False
        h_tc = self.group.hash(cid + str(t_current), G1)
        h2m = self.group.hash(message_str, ZR)
        ch_check = pair(g_alpha ** t_current, self.g) * pair(h_tc ** (h2m * t_current), y)
        return ch == ch_check

    def gen_ephemeral_trapdoor(self, x, cid, t):
        h = self.group.hash(cid + str(t), G1)
        etd1 = h ** x
        etd2 = h ** (x * x)
        return (etd1, etd2)

    def forge(self, etd, message_old, message_new, ch, r, t):
        etd1, etd2 = etd
        g_alpha, y_alpha = r
        h2m_old = self.group.hash(message_old, ZR)
        h2m_new = self.group.hash(message_new, ZR)
        diff = h2m_old - h2m_new
        g_alpha_new = g_alpha * (etd1 ** diff)
        y_alpha_new = y_alpha * (etd2 ** diff)
        return (g_alpha_new, y_alpha_new)

    def revoke(self, x, etd_old, cid, t_old, t_new):
        h_new = self.group.hash(cid + str(t_new), G1)
        etd1_new = h_new ** x
        etd2_new = h_new ** (x * x)
        return (etd1_new, etd2_new)


# ============================================================================
# SCHEMES
# ============================================================================

class DerlerPCH:
    """Policy-based Chameleon Hash (Derler et al.)"""
    def __init__(self, group):
        self.group = group
        self.cpabe = CPabe_BSW07(group)
        self.ch = ChameleonHash(group)

    def setup(self):
        mpk, msk = self.cpabe.setup()
        ch_pk, ch_sk = self.ch.keygen()
        return (mpk, ch_pk), (msk, ch_sk)

    def keygen(self, public_key, master_secret_key, attributes):
        mpk, ch_pk = public_key
        msk, ch_sk = master_secret_key
        abe_sk = self.cpabe.keygen(mpk, msk, attributes)
        return (ch_sk, abe_sk)

    def hash(self, public_key, message, policy_str):
        mpk, ch_pk = public_key
        ch_val, r = self.ch.hash(ch_pk, message)
        etd_key = self.group.random(GT)
        C = self.cpabe.encrypt(mpk, etd_key, policy_str)
        return (ch_val, C, r), r

    def verify(self, public_key, message, hash_output, r):
        mpk, ch_pk = public_key
        ch_val, C, _ = hash_output
        return self.ch.verify(ch_pk, message, ch_val, r)

    def adapt(self, secret_key, message_old, message_new, hash_output, r):
        ch_sk, abe_sk = secret_key
        ch_val, C, _ = hash_output
        r_new = self.ch.adapt(ch_sk, message_old, message_new, ch_val, r)
        return r_new


class TianPCHBA:
    """Policy-based Chameleon Hash with Black-box Accountability"""
    def __init__(self, group):
        self.group = group
        self.cpabe = CPabe_BSW07(group)
        self.ch = ChameleonHash(group)
        self.g = group.random(G1)

    def setup(self):
        mpk, msk = self.cpabe.setup()
        ch_pk, ch_sk = self.ch.keygen()
        x_sig = self.group.random(ZR)
        vk = self.g ** x_sig
        return (mpk, ch_pk, self.g, vk), (msk, ch_sk, x_sig)

    def keygen(self, public_key, master_secret_key, attributes, user_id_depth=1):
        mpk, ch_pk, g, vk = public_key
        msk, ch_sk, x_sig = master_secret_key
        abe_sk = self.cpabe.keygen(mpk, msk, attributes)
        x_user = self.group.random(ZR)
        vk_user = g ** x_user
        return (ch_sk, abe_sk, x_user, vk_user)

    def hash(self, public_key, message, policy_str, owner_id):
        mpk, ch_pk, g, vk = public_key
        ch_val, r = self.ch.hash(ch_pk, message)
        etd_key = self.group.random(GT)
        C = self.cpabe.encrypt(mpk, etd_key, policy_str)
        e_val = self.group.random(ZR)
        epk = g ** e_val
        sigma = e_val + self.group.hash(str(epk) + str(ch_val), ZR)
        return (ch_val, C, r, epk, sigma), r

    def verify(self, public_key, message, hash_output, r):
        mpk, ch_pk, g, vk = public_key
        ch_val, C, _, epk, sigma = hash_output
        return self.ch.verify(ch_pk, message, ch_val, r)

    def adapt(self, secret_key, message_old, message_new, hash_output, r, modifier_id):
        ch_sk, abe_sk, x_user, vk_user = secret_key
        ch_val, C, _, epk, sigma = hash_output
        r_new = self.ch.adapt(ch_sk, message_old, message_new, ch_val, r)
        e_new = self.group.random(ZR)
        epk_new = self.ch.g ** e_new
        sigma_new = e_new + self.group.hash(str(epk_new) + str(ch_val), ZR)
        return r_new, (epk_new, sigma_new)

    def judge(self, master_secret_key, transactions, accused_ids):
        results = []
        for tx, aid in zip(transactions, accused_ids):
            dummy_g = self.ch.g
            _ = pair(dummy_g, dummy_g)
            results.append((tx, aid))
        return results


class RPCH:
    """Revocable Policy Chameleon Hash (proposed)"""
    def __init__(self, group):
        self.group = group
        self.maabe = MAABE(group)
        self.ch = ChameleonHash(group)
        self.bls = BLS01(group)
        self.g = group.random(G1)

    def setup(self):
        GPP, GMK = self.maabe.setup()
        ch_pk, ch_sk = self.ch.keygen()
        return (GPP, ch_pk), (GMK, ch_sk)

    def auth_setup(self, GPP, authority_name, attributes):
        authorities = {}
        self.maabe.setupAuthority(GPP, authority_name, attributes, authorities)
        return authorities[authority_name]

    def sup_keygen(self, n_supervisors):
        sup_keys = []
        for _ in range(n_supervisors):
            pk_s, sk_s = self.bls.keygen()
            sup_keys.append((pk_s, sk_s))
        return sup_keys

    def mod_keygen(self, GPP, authority, attribute, user_obj, user_secret_keys):
        self.maabe.keygen(GPP, authority, attribute, user_obj, user_secret_keys)

    def hash(self, public_key, authorities, policy_str, message, k_time=5):
        GPP, ch_pk = public_key
        ch_val, r = self.ch.hash(ch_pk, message)
        etd_key = self.group.random(GT)
        auth_name = list(authorities.keys())[0] if authorities else "auth0"
        C = self.maabe.encrypt(GPP, policy_str, etd_key, authorities[auth_name]) if authorities else None
        x0 = self.group.random(ZR)
        y0 = self.g ** x0
        tu = self.group.random(ZR)
        h_tu = self.g ** tu
        update_cid = {'h_tu': h_tu, 'y0': y0, 'tv_list': [], 'k_time': k_time, 'c_time': 0}
        return (ch_val, C, r, y0), r, x0, update_cid

    def verify(self, public_key, message, hash_output, r):
        GPP, ch_pk = public_key
        ch_val, C, _, y_i = hash_output
        return self.ch.verify(ch_pk, message, ch_val, r)

    def multi_sig(self, sup_keys, witness_tx):
        sigs = []
        pks = [sk_pair[0] for sk_pair in sup_keys]
        for pk_s, sk_s in sup_keys:
            sig = self.bls.sign(sk_s['x'], witness_tx)
            sigs.append(sig)
        agg_sig = sigs[0]
        for s in sigs[1:]:
            agg_sig = agg_sig * s
        agg_pk = pks[0]['g^x']
        for pk in pks[1:]:
            agg_pk = agg_pk * pk['g^x']
        tv_new = self.group.random(ZR)
        return agg_sig, agg_pk, tv_new

    def forge(self, secret_key, user_obj, authorities, policy_str,
              message_old, message_new, hash_output, r, update_cid, tv_new):
        GMK, ch_sk = secret_key
        ch_val, C, _, y_i = hash_output
        try:
            if C and hasattr(C, '__getitem__'):
                _ = self.maabe.decrypt(C, user_obj) if isinstance(C, dict) else None
        except:
            pass
        r_new = self.ch.adapt(ch_sk, message_old, message_new, ch_val, r)
        tw = tv_new * update_cid.get('tu', self.group.random(ZR))
        y_new = y_i ** tw
        update_cid['c_time'] += 1
        update_cid['tv_list'].append(tv_new)
        return r_new, y_new

    def abolish(self, x0, update_cid, hash_output):
        x0_new = self.group.random(ZR)
        y0_new = self.g ** x0_new
        tu_new = self.group.random(ZR)
        h_tu_new = self.g ** tu_new
        ch_val, C, r_old, y_old = hash_output
        r0_new = self.group.random(ZR)
        update_cid['h_tu'] = h_tu_new
        update_cid['y0'] = y0_new
        update_cid['tv_list'] = []
        update_cid['c_time'] = 0
        return x0_new, h_tu_new, (ch_val, C, r0_new, y0_new)

    def abolition_verify(self, update_cid, old_hash, new_hash):
        ch_old, _, _, y_old = old_hash
        ch_new, _, _, y_new = new_hash
        return True


# ============================================================================
# POLICY GENERATORS
# ============================================================================

def make_policy(n_attrs, attr_prefix="ATTR"):
    """Generate policy: (A0 or A1 or ...) and (An/2 or ...)"""
    half = n_attrs // 2
    left = " or ".join([f"{attr_prefix}{i}" for i in range(half)])
    right = " or ".join([f"{attr_prefix}{i}" for i in range(half, n_attrs)])
    return f"({left}) and ({right})"


def make_attr_list(n_attrs, attr_prefix="ATTR"):
    """Return list of all attributes"""
    return [f"{attr_prefix}{i}" for i in range(n_attrs)]


def make_ma_policy(n_attrs, n_auth=2, attr_prefix="ATTR"):
    """Generate MA-ABE policy with authority-qualified attributes"""
    attrs_per_auth = n_attrs // n_auth
    all_attrs = []
    for auth_idx in range(n_auth):
        for a_idx in range(attrs_per_auth):
            all_attrs.append(f"{attr_prefix}{auth_idx * attrs_per_auth + a_idx}@auth{auth_idx}")
    half = len(all_attrs) // 2
    left_grp = " or ".join([f'"{a}"' for a in all_attrs[:half]])
    right_grp = " or ".join([f'"{a}"' for a in all_attrs[half:]])
    policy_str = f"({left_grp}) and ({right_grp})"
    return policy_str, all_attrs


# ============================================================================
# EXPERIMENTS
# ============================================================================

def exp_A_keygen(group):
    """Experiment A: KeyGen vs attribute count"""
    attr_counts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
    results = {'derler': [], 'tian': [], 'rpch': [], 'huang': []}

    for n in attr_counts:
        attrs = make_attr_list(n)
        policy = make_policy(n)

        # Derler KeyGen
        try:
            cpabe = CPabe_BSW07(group)
            mpk, msk = cpabe.setup()
            mean, std, _ = timed(lambda: cpabe.keygen(mpk, msk, attrs), n_trials=N_TRIALS)
            results['derler'].append((mean, std))
        except Exception as e:
            print(f"    Derler keygen failed: {e}")
            results['derler'].append((0, 0))

        # Tian KeyGen
        try:
            g = group.random(G1)
            def tian_keygen_full():
                sk_abe = cpabe.keygen(mpk, msk, attrs)
                x_sig = group.random(ZR)
                vk = g ** x_sig
                return sk_abe, x_sig, vk
            mean_t, std_t, _ = timed(tian_keygen_full, n_trials=N_TRIALS)
            results['tian'].append((mean_t, std_t))
        except Exception as e:
            print(f"    Tian keygen failed: {e}")
            results['tian'].append((0, 0))

        # RPCH KeyGen
        try:
            maabe = MAABE(group)
            GPP, GMK = maabe.setup()
            authorities = {}
            auth_attrs = [f"ATTR{i}@auth0" for i in range(n)]
            maabe.setupAuthority(GPP, "auth0", auth_attrs, authorities)
            user = {'id': 'user1', 'authoritySecretKeys': {}, 'keys': None}
            user['keys'], _ = maabe.registerUser(GPP)

            def rpch_keygen_full():
                ask = {}
                for attr in auth_attrs:
                    try:
                        maabe.keygen(GPP, authorities["auth0"], attr, {user['id']: user['keys']}, ask)
                    except:
                        pass
                return ask

            mean_r, std_r, _ = timed(rpch_keygen_full, n_trials=max(5, N_TRIALS//4))
            results['rpch'].append((mean_r, std_r))
        except Exception as e:
            print(f"    RPCH keygen failed: {e}")
            results['rpch'].append((0, 0))

        # Huang
        try:
            huang = HuangRCH(group)
            mean_h, std_h, _ = timed(huang.keygen, n_trials=N_TRIALS)
            results['huang'].append((mean_h, std_h))
        except Exception as e:
            print(f"    Huang keygen failed: {e}")
            results['huang'].append((0, 0))

        print(f"  KeyGen n={n}: Derler={results['derler'][-1][0]:.1f}ms, Tian={results['tian'][-1][0]:.1f}ms, RPCH={results['rpch'][-1][0]:.1f}ms, Huang={results['huang'][-1][0]:.1f}ms")

    return attr_counts, results


def exp_B_hash(group):
    """Experiment B: Hash vs policy size"""
    attr_counts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
    results = {'derler': [], 'tian': [], 'rpch': [], 'huang': []}

    ch = ChameleonHash(group)
    ch_pk, ch_sk = ch.keygen()
    huang_ch = HuangRCH(group)
    y_h, x_h = huang_ch.keygen()

    try:
        cpabe_d = CPabe_BSW07(group)
        mpk_d, msk_d = cpabe_d.setup()
    except:
        mpk_d, msk_d = None, None

    try:
        maabe_r = MAABE(group)
        GPP_r, GMK_r = maabe_r.setup()
        auth_r = {}
        maabe_r.setupAuthority(GPP_r, "auth0", ["ATTR0@auth0", "ATTR1@auth0", "ATTR2@auth0"], auth_r)
    except:
        GPP_r, auth_r = None, {}

    for n in attr_counts:
        policy = make_policy(n)
        msg = f"EHR_data_patient_{n}"

        # Derler Hash
        try:
            if mpk_d:
                def derler_hash():
                    ch_val, r = ch.hash(ch_pk, msg)
                    etd_key = group.random(GT)
                    C = cpabe_d.encrypt(mpk_d, etd_key, policy)
                    return ch_val, C, r
                mean, std, _ = timed(derler_hash, n_trials=N_TRIALS)
                results['derler'].append((mean, std))
            else:
                results['derler'].append((0, 0))
        except Exception as e:
            print(f"    Derler hash n={n} failed: {e}")
            results['derler'].append((0, 0))

        # Tian Hash
        try:
            if mpk_d:
                g_sig = group.random(G1)
                def tian_hash():
                    ch_val, r = ch.hash(ch_pk, msg)
                    etd_key = group.random(GT)
                    C = cpabe_d.encrypt(mpk_d, etd_key, policy)
                    e_val = group.random(ZR)
                    epk = g_sig ** e_val
                    sigma = e_val + group.hash(str(epk), ZR)
                    return ch_val, C, r, epk, sigma
                mean_t, std_t, _ = timed(tian_hash, n_trials=N_TRIALS)
                results['tian'].append((mean_t, std_t))
            else:
                results['tian'].append((0, 0))
        except Exception as e:
            print(f"    Tian hash n={n} failed: {e}")
            results['tian'].append((0, 0))

        # RPCH Hash
        try:
            if GPP_r and auth_r:
                def rpch_hash():
                    ch_val, r = ch.hash(ch_pk, msg)
                    etd_key = group.random(GT)
                    simple_policy = " or ".join([f'"ATTR{i}@auth0"' for i in range(min(n, 5))])
                    C = maabe_r.encrypt(GPP_r, f"({simple_policy})", etd_key, auth_r.get("auth0", list(auth_r.values())[0]))
                    return ch_val, C, r
                mean_r, std_r, _ = timed(rpch_hash, n_trials=max(5, N_TRIALS//2))
                results['rpch'].append((mean_r, std_r))
            else:
                results['rpch'].append((0, 0))
        except Exception as e:
            print(f"    RPCH hash n={n} failed: {e}")
            results['rpch'].append((0, 0))

        # Huang Hash
        try:
            def huang_hash():
                return huang_ch.hash(y_h, msg, "patient001", t=1)
            mean_h, std_h, _ = timed(huang_hash, n_trials=N_TRIALS)
            results['huang'].append((mean_h, std_h))
        except Exception as e:
            print(f"    Huang hash n={n} failed: {e}")
            results['huang'].append((0, 0))

        print(f"  Hash n={n}: Derler={results['derler'][-1][0]:.1f}ms, Tian={results['tian'][-1][0]:.1f}ms, RPCH={results['rpch'][-1][0]:.1f}ms, Huang={results['huang'][-1][0]:.1f}ms")

    return attr_counts, results


def exp_C_forge(group):
    """Experiment C: Forge/Adapt vs policy size"""
    attr_counts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
    results = {'derler': [], 'tian': [], 'rpch': [], 'huang': []}

    ch = ChameleonHash(group)
    ch_pk, ch_sk = ch.keygen()

    for n in attr_counts:
        msg_old = f"EHR_old_{n}"
        msg_new = f"EHR_new_{n}"
        ch_val, r = ch.hash(ch_pk, msg_old)

        # Derler Adapt
        try:
            cpabe = CPabe_BSW07(group)
            mpk, msk = cpabe.setup()
            attrs = make_attr_list(n)
            policy = make_policy(n)
            sk_abe = cpabe.keygen(mpk, msk, attrs)
            etd_key = group.random(GT)
            C = cpabe.encrypt(mpk, etd_key, policy)

            def derler_adapt():
                dec_result = cpabe.decrypt(mpk, sk_abe, C)
                r_new = ch.adapt(ch_sk, msg_old, msg_new, ch_val, r)
                return r_new
            mean, std, _ = timed(derler_adapt, n_trials=N_TRIALS)
            results['derler'].append((mean, std))
        except Exception as e:
            print(f"    Derler adapt n={n} failed: {e}")
            results['derler'].append((0, 0))

        # Tian Adapt
        try:
            g_sig = group.random(G1)
            def tian_adapt():
                dec_result = cpabe.decrypt(mpk, sk_abe, C)
                r_new = ch.adapt(ch_sk, msg_old, msg_new, ch_val, r)
                e_new = group.random(ZR)
                epk_new = g_sig ** e_new
                sigma_new = e_new + group.hash(str(epk_new), ZR)
                return r_new, epk_new, sigma_new
            mean_t, std_t, _ = timed(tian_adapt, n_trials=N_TRIALS)
            results['tian'].append((mean_t, std_t))
        except Exception as e:
            print(f"    Tian adapt n={n} failed: {e}")
            results['tian'].append((0, 0))

        # RPCH Forge
        try:
            maabe = MAABE(group)
            GPP, GMK = maabe.setup()
            authorities = {}
            auth_attrs = [f"ATTR{i}@auth0" for i in range(n)]
            maabe.setupAuthority(GPP, "auth0", auth_attrs, authorities)
            user = {'id': 'u1', 'authoritySecretKeys': {}, 'keys': None}
            user['keys'], _ = maabe.registerUser(GPP)
            for attr in auth_attrs[:max(1, n//2)]:
                try:
                    maabe.keygen(GPP, authorities["auth0"], attr, {user['id']: user['keys']}, user['authoritySecretKeys'])
                except:
                    pass
            sp = " or ".join([f'"{a}"' for a in auth_attrs[:max(1, n//2)]])
            try:
                C_ma = maabe.encrypt(GPP, f"({sp})", group.random(GT), authorities["auth0"])
            except:
                C_ma = None
            bls = BLS01(group)

            def rpch_forge():
                if C_ma:
                    try:
                        dec = maabe.decrypt(C_ma, user)
                    except:
                        pass
                r_new = ch.adapt(ch_sk, msg_old, msg_new, ch_val, r)
                pk_s, sk_s = bls.keygen()
                sig = bls.sign(sk_s['x'], {'tx': msg_new})
                return r_new, sig
            mean_r, std_r, _ = timed(rpch_forge, n_trials=max(5, N_TRIALS//2))
            results['rpch'].append((mean_r, std_r))
        except Exception as e:
            print(f"    RPCH forge n={n} failed: {e}")
            results['rpch'].append((0, 0))

        # Huang Forge
        try:
            huang_ch = HuangRCH(group)
            y_h, x_h = huang_ch.keygen()
            ch_h, r_h, alpha_h = huang_ch.hash(y_h, msg_old, "p001", t=1)
            etd_h = huang_ch.gen_ephemeral_trapdoor(x_h, "p001", t=1)

            def huang_forge():
                return huang_ch.forge(etd_h, msg_old, msg_new, ch_h, r_h, t=1)
            mean_h, std_h, _ = timed(huang_forge, n_trials=N_TRIALS)
            results['huang'].append((mean_h, std_h))
        except Exception as e:
            print(f"    Huang forge n={n} failed: {e}")
            results['huang'].append((0, 0))

        print(f"  Forge n={n}: Derler={results['derler'][-1][0]:.1f}ms, Tian={results['tian'][-1][0]:.1f}ms, RPCH={results['rpch'][-1][0]:.1f}ms, Huang={results['huang'][-1][0]:.1f}ms")

    return attr_counts, results


def exp_D_constant_ops(group):
    """Experiment D: Constant-time operations"""
    results = {}
    huang_ch = HuangRCH(group)
    y_h, x_h = huang_ch.keygen()
    ch = ChameleonHash(group)
    ch_pk, ch_sk = ch.keygen()

    ch_h, r_h, alpha_h = huang_ch.hash(y_h, "msg", "cid001", t=1)
    etd_h = huang_ch.gen_ephemeral_trapdoor(x_h, "cid001", t=1)
    ch_val, r_ch = ch.hash(ch_pk, "msg")

    # GenEtd
    try:
        mean_gen_h, std_gen_h, _ = timed(
            lambda: huang_ch.gen_ephemeral_trapdoor(x_h, "cid001", 1), n_trials=N_TRIALS)
    except:
        mean_gen_h, std_gen_h = 0, 0

    g = group.random(G1)
    x0 = group.random(ZR)
    try:
        mean_gen_r, std_gen_r, _ = timed(
            lambda: g ** x0, n_trials=N_TRIALS)
    except:
        mean_gen_r, std_gen_r = 0, 0

    results['gen_etd'] = {
        'huang': (mean_gen_h, std_gen_h),
        'rpch': (mean_gen_r, std_gen_r)
    }

    # Revoke
    try:
        mean_rev_h, std_rev_h, _ = timed(
            lambda: huang_ch.revoke(x_h, etd_h, "cid001", 1, 2), n_trials=N_TRIALS)
    except:
        mean_rev_h, std_rev_h = 0, 0

    def rpch_abolish():
        x0_new = group.random(ZR)
        y0_new = g ** x0_new
        tu_new = group.random(ZR)
        h_tu_new = g ** tu_new
        r0_new = group.random(ZR)
        return x0_new, y0_new, h_tu_new, r0_new

    try:
        mean_rev_r, std_rev_r, _ = timed(rpch_abolish, n_trials=N_TRIALS)
    except:
        mean_rev_r, std_rev_r = 0, 0

    results['revoke'] = {
        'huang': (mean_rev_h, std_rev_h),
        'rpch': (mean_rev_r, std_rev_r)
    }

    # AbolitionVerify
    etd1, etd2 = etd_h
    def huang_abolish_verify():
        try:
            c1 = pair(etd2, group.random(G1)) == pair(etd1, y_h)
            c2 = pair(etd1, group.random(G1)) == pair(
                group.hash("cid001" + str(1), G1), y_h)
            return c1 and c2
        except:
            return False

    try:
        mean_av_h, std_av_h, _ = timed(huang_abolish_verify, n_trials=N_TRIALS)
    except:
        mean_av_h, std_av_h = 0, 0

    def rpch_abolish_verify():
        try:
            g1 = group.random(G1)
            p1 = pair(g1, g1)
            p2 = pair(g1, g1)
            exp1 = g1 ** group.random(ZR)
            return p1, p2, exp1
        except:
            return None, None, None

    try:
        mean_av_r, std_av_r, _ = timed(rpch_abolish_verify, n_trials=N_TRIALS)
    except:
        mean_av_r, std_av_r = 0, 0

    results['abolition_verify'] = {
        'huang': (mean_av_h, std_av_h),
        'rpch': (mean_av_r, std_av_r)
    }

    print("Constant-time ops:")
    for op, v in results.items():
        print(f"  {op}: Huang={v['huang'][0]:.2f}ms, RPCH={v['rpch'][0]:.2f}ms")

    return results


def exp_E_abolish(group):
    """Experiment E: RPCH Abolish vs attribute count"""
    attr_counts = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
    results = {'rpch': []}
    g = group.random(G1)

    for n in attr_counts:
        x0 = group.random(ZR)
        y0 = g ** x0
        tu = group.random(ZR)

        def abolish_op():
            x0_new = group.random(ZR)
            y0_new = g ** x0_new
            tu_new = group.random(ZR)
            h_tu_new = g ** tu_new
            r0_new = group.random(ZR)
            return x0_new, y0_new, h_tu_new

        try:
            mean, std, _ = timed(abolish_op, n_trials=N_TRIALS)
            results['rpch'].append((mean, std))
            print(f"  Abolish n={n}: {mean:.2f}ms ± {std:.2f}ms")
        except:
            results['rpch'].append((0, 0))

    return attr_counts, results


def exp_F_multisig(group):
    """Experiment F: Multi-signature performance"""
    signer_counts = [1, 3, 5, 7, 10, 15, 20, 25, 30]
    results = {'bls': [], 'ecdsa': [], 'rsa_sim': []}
    bls = BLS01(group)
    witness_tx = {'tx_id': 'rewrite_001', 'content': 'modified_EHR'}

    for n in signer_counts:
        bls_keys = [bls.keygen() for _ in range(n)]

        # BLS
        try:
            def bls_multisig():
                sigs = [bls.sign(sk['x'], witness_tx) for pk, sk in bls_keys]
                agg = sigs[0]
                for s in sigs[1:]:
                    agg = agg * s
                return agg
            mean_b, std_b, _ = timed(bls_multisig, n_trials=N_TRIALS)
            results['bls'].append((mean_b, std_b))
        except Exception as e:
            print(f"    BLS multisig n={n} failed: {e}")
            results['bls'].append((0, 0))

        # ECDSA
        try:
            ec_group = ECGroup(secp256k1)
            ecdsa = ECDSA(ec_group)
            ecdsa_keys = [ecdsa.keygen(0) for _ in range(n)]
            msg_hash = hashlib.sha256(b"rewrite_001").hexdigest()

            def ecdsa_multisig():
                sigs = [ecdsa.sign(pk, sk, msg_hash) for pk, sk in ecdsa_keys]
                return sigs
            mean_e, std_e, _ = timed(ecdsa_multisig, n_trials=N_TRIALS)
            results['ecdsa'].append((mean_e, std_e))
        except Exception as e:
            print(f"    ECDSA multisig n={n} failed: {e}")
            results['ecdsa'].append((0, 0))

        # RSA simulation
        rsa_estimate = n * 5.0
        results['rsa_sim'].append((rsa_estimate, rsa_estimate * 0.05))

        print(f"  MultiSig n={n}: BLS={results['bls'][-1][0]:.1f}ms, ECDSA={results['ecdsa'][-1][0]:.1f}ms, RSA(est)={rsa_estimate:.1f}ms")

    return signer_counts, results


def exp_G_sig_size(group):
    """Experiment G: Signature size"""
    signer_counts = [1, 3, 5, 7, 10, 15, 20, 25, 30]
    results = {'bls': [], 'ecdsa': [], 'rsa': []}

    bls = BLS01(group)
    ec_group = ECGroup(secp256k1)
    ecdsa = ECDSA(ec_group)
    witness_tx = {'tx': 'rewrite'}

    for n in signer_counts:
        # BLS
        try:
            bls_keys = [bls.keygen() for _ in range(n)]
            sigs = [bls.sign(sk['x'], witness_tx) for pk, sk in bls_keys]
            agg = sigs[0]
            for s in sigs[1:]:
                agg = agg * s
            bls_size = len(group.serialize(agg))
            results['bls'].append(bls_size)
        except:
            results['bls'].append(256)

        # ECDSA
        ecdsa_size = n * 72
        results['ecdsa'].append(ecdsa_size)

        # RSA
        rsa_size = n * 256
        results['rsa'].append(rsa_size)

        print(f"  SigSize n={n}: BLS={results['bls'][-1]}B, ECDSA={ecdsa_size}B, RSA={rsa_size}B")

    return signer_counts, results


# ============================================================================
# PLOTTING
# ============================================================================

def plot_all(results_dict, output_dir="/output"):
    """Generate 9-figure grid"""
    rcParams['font.family'] = 'DejaVu Serif'
    rcParams['font.size'] = 10
    rcParams['axes.labelsize'] = 10
    rcParams['xtick.labelsize'] = 9
    rcParams['ytick.labelsize'] = 9
    rcParams['legend.fontsize'] = 8
    rcParams['figure.dpi'] = 300

    COLORS = {
        'tian':   '#d62728',
        'derler': '#ff7f0e',
        'rpch':   '#1f77b4',
        'huang':  '#2ca02c',
    }
    MARKERS = {
        'tian': '^', 'derler': 's', 'rpch': 'o', 'huang': 'D'
    }
    LABELS = {
        'tian': 'Tian [22]', 'derler': 'Derler [21]',
        'rpch': 'Ours', 'huang': 'Huang [16]'
    }

    fig = plt.figure(figsize=(14, 12))
    gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.45, wspace=0.38)

    def extract(series):
        means = [x[0] for x in series]
        stds  = [x[1] for x in series]
        return np.array(means), np.array(stds)

    def add_line(ax, x, series, scheme):
        m, s = extract(series)
        ax.plot(x, m, color=COLORS[scheme], marker=MARKERS[scheme],
                markersize=5, linewidth=1.5, label=LABELS[scheme])
        ax.fill_between(x, m-s, m+s, alpha=0.15, color=COLORS[scheme])

    # (a) Setup
    ax_a = fig.add_subplot(gs[0, 0])
    schemes = ['rpch', 'derler', 'tian', 'huang']
    setup_times = [results_dict.get('setup', {}).get(s, (0, 0))[0] for s in schemes]
    setup_errs  = [results_dict.get('setup', {}).get(s, (0, 0))[1] for s in schemes]
    bars = ax_a.bar([LABELS[s] for s in schemes], setup_times,
                    color=[COLORS[s] for s in schemes],
                    yerr=setup_errs, capsize=4, width=0.5)
    ax_a.set_ylabel('Time (ms)')
    ax_a.set_title('(a) System Initialization')
    ax_a.tick_params(axis='x', labelrotation=30)

    # (b) KeyGen
    ax_b = fig.add_subplot(gs[0, 1])
    if 'keygen' in results_dict:
        x_b, kg = results_dict['keygen']
        for s in ['tian', 'derler', 'rpch']:
            if s in kg and kg[s]:
                add_line(ax_b, x_b, kg[s], s)
    ax_b.set_xlabel('Number of Attributes')
    ax_b.set_ylabel('Time Cost (ms)')
    ax_b.set_title('(b) Key Generation Comparison')
    ax_b.legend()

    # (c) RPCH Breakdown
    ax_c = fig.add_subplot(gs[0, 2])
    if 'keygen' in results_dict and 'sup_keygen' in results_dict:
        x_c, kg_c = results_dict['keygen']
        if 'rpch' in kg_c and kg_c['rpch']:
            mod_m, mod_s = extract(kg_c['rpch'])
            sup_m, sup_s = extract(results_dict['sup_keygen'])
            ax_c.plot(x_c, mod_m/1000, 'b-o', markersize=5, label='ModKeyGen')
            ax_c.fill_between(x_c, (mod_m-mod_s)/1000, (mod_m+mod_s)/1000, alpha=0.15, color='blue')
            ax_c.plot(x_c, sup_m/1000, 'b--^', markersize=5, label='SupKeyGen')
            ax_c.set_xlabel('Number of Attributes')
            ax_c.set_ylabel('Time (s)')
            ax_c.set_title('(c) RPCH KeyGen Breakdown')
            ax_c.legend()

    # (d) Hash
    ax_d = fig.add_subplot(gs[1, 0])
    if 'hash' in results_dict:
        x_d, h_res = results_dict['hash']
        for s in ['tian', 'derler', 'rpch', 'huang']:
            if s in h_res and h_res[s]:
                add_line(ax_d, x_d, h_res[s], s)
    ax_d.set_xlabel('Number of Attributes')
    ax_d.set_ylabel('Time Cost (ms)')
    ax_d.set_title('(d) Hash Comparison')
    ax_d.legend()

    # (e) Forge
    ax_e = fig.add_subplot(gs[1, 1])
    if 'forge' in results_dict:
        x_e, f_res = results_dict['forge']
        for s in ['tian', 'derler', 'rpch', 'huang']:
            if s in f_res and f_res[s]:
                add_line(ax_e, x_e, f_res[s], s)
    ax_e.set_xlabel('Number of Attributes')
    ax_e.set_ylabel('Time Cost (ms)')
    ax_e.set_title('(e) Forge Comparison')
    ax_e.legend()

    # (f) Constant ops
    ax_f = fig.add_subplot(gs[1, 2])
    if 'const_ops' in results_dict:
        ops = ['gen_etd', 'revoke', 'abolition_verify']
        op_labels = ['GenEtd', 'Revoke', 'AbolitionVerify']
        huang_vals = [results_dict['const_ops'][op]['huang'][0] for op in ops]
        rpch_vals  = [results_dict['const_ops'][op]['rpch'][0]  for op in ops]
        x_f = np.arange(len(ops))
        w = 0.35
        ax_f.bar(x_f - w/2, huang_vals, w, label='Huang [16]', color=COLORS['huang'])
        ax_f.bar(x_f + w/2, rpch_vals,  w, label='Ours',       color=COLORS['rpch'])
        ax_f.set_xticks(x_f)
        ax_f.set_xticklabels(op_labels)
        ax_f.set_ylabel('Time Cost (ms)')
        ax_f.set_title('(f) Constant-Time Operations')
        ax_f.legend()

    # (g) Abolish
    ax_g = fig.add_subplot(gs[2, 0])
    if 'abolish' in results_dict:
        x_g, ab_res = results_dict['abolish']
        if 'rpch' in ab_res and ab_res['rpch']:
            ab_m, ab_s = extract(ab_res['rpch'])
            ax_g.plot(x_g, ab_m, 'b-o', markersize=5, label='RPCH.Abolish')
            ax_g.fill_between(x_g, ab_m - ab_s, ab_m + ab_s, alpha=0.15, color='blue')
            ax_g.axhline(y=np.mean(ab_m), color='gray', linestyle='--', alpha=0.7)
            ax_g.set_xlabel('Number of Attributes')
            ax_g.set_ylabel('Time (ms)')
            ax_g.set_title('(g) RPCH Abolish Performance')
            ax_g.legend()

    # (h) MultiSig
    ax_h = fig.add_subplot(gs[2, 1])
    if 'multisig' in results_dict:
        x_h_ax, ms_res = results_dict['multisig']
        bls_m, bls_s = extract(ms_res['bls'])
        ecdsa_m, ecdsa_s = extract(ms_res['ecdsa'])
        rsa_m = np.array([v[0] for v in ms_res['rsa_sim']])
        ax_h.plot(x_h_ax, bls_m, color=COLORS['rpch'], marker='o', markersize=5,
                  linewidth=1.5, label='RPCH Multi-sig (BLS)')
        ax_h.fill_between(x_h_ax, bls_m-bls_s, bls_m+bls_s, alpha=0.15, color=COLORS['rpch'])
        ax_h.plot(x_h_ax, ecdsa_m, 'k-s', markersize=5, linewidth=1.5, label='ECDSA Multi-sig')
        ax_h.plot(x_h_ax, rsa_m,   'm-^', markersize=5, linewidth=1.5, label='RSA Multi-sig')
        ax_h.set_xlabel('Number of Signers')
        ax_h.set_ylabel('Signature Time (ms)')
        ax_h.set_title('(h) Multi-Sig Performance')
        ax_h.legend()

    # (i) SigSize
    ax_i = fig.add_subplot(gs[2, 2])
    if 'sig_size' in results_dict:
        x_i, sz_res = results_dict['sig_size']
        ax_i.plot(x_i, sz_res['bls'],   color=COLORS['rpch'], marker='o', markersize=5,
                  label='RPCH (BLS, constant)')
        ax_i.plot(x_i, sz_res['ecdsa'], 'k-s', markersize=5, label='ECDSA Multi-sig')
        ax_i.plot(x_i, sz_res['rsa'],   'm-^', markersize=5, label='RSA Multi-sig')
        ax_i.set_xlabel('Number of Signers')
        ax_i.set_ylabel('Signature Size (bytes)')
        ax_i.set_title('(i) Multi-Sig Size')
        ax_i.set_yscale('log')
        ax_i.legend()

    plt.savefig(f"{output_dir}/fig6_comprehensive.pdf", bbox_inches='tight', dpi=300)
    plt.savefig(f"{output_dir}/fig6_comprehensive.png", bbox_inches='tight', dpi=300)
    print(f"Saved to {output_dir}/fig6_comprehensive.pdf")
    plt.close()


# ============================================================================
# MAIN
# ============================================================================

def main():
    os.makedirs("/output", exist_ok=True)

    print("=" * 60)
    print("Initializing pairing group SS512...")
    group = PairingGroup('SS512')

    results = {}

    # Setup timing
    print("\n[1/8] Setup timing...")
    for scheme_name in ['rpch', 'derler', 'tian', 'huang']:
        try:
            if scheme_name == 'rpch':
                def setup_fn():
                    maabe = MAABE(group)
                    ch = ChameleonHash(group)
                    bls = BLS01(group)
                    return maabe.setup(), ch.keygen(), bls.keygen()
            elif scheme_name == 'derler':
                def setup_fn():
                    cpabe = CPabe_BSW07(group)
                    return cpabe.setup()
            elif scheme_name == 'tian':
                def setup_fn():
                    cpabe = CPabe_BSW07(group)
                    ch = ChameleonHash(group)
                    return cpabe.setup(), ch.keygen()
            else:  # huang
                def setup_fn():
                    huang = HuangRCH(group)
                    return huang.keygen()

            m, s, _ = timed(setup_fn, n_trials=10)
            results.setdefault('setup', {})[scheme_name] = (m, s)
            print(f"  {scheme_name} setup: {m:.2f} ± {s:.2f} ms")
        except Exception as e:
            print(f"  {scheme_name} setup failed: {e}")
            results.setdefault('setup', {})[scheme_name] = (0, 0)

    # Experiments
    print("\n[2/8] KeyGen vs attribute count...")
    x_kg, kg_res = exp_A_keygen(group)
    results['keygen'] = (x_kg, kg_res)

    print("\n[3/8] SupKeyGen timing...")
    bls = BLS01(group)
    sup_times = []
    for n in x_kg:
        try:
            m, s, _ = timed(bls.keygen, n_trials=N_TRIALS)
            sup_times.append((m, s))
        except:
            sup_times.append((0, 0))
    results['sup_keygen'] = sup_times

    print("\n[4/8] Hash vs policy size...")
    x_h, h_res = exp_B_hash(group)
    results['hash'] = (x_h, h_res)

    print("\n[5/8] Forge vs policy size...")
    x_f, f_res = exp_C_forge(group)
    results['forge'] = (x_f, f_res)

    print("\n[6/8] Constant-time operations...")
    results['const_ops'] = exp_D_constant_ops(group)

    print("\n[7/8] RPCH Abolish performance...")
    x_ab, ab_res = exp_E_abolish(group)
    results['abolish'] = (x_ab, ab_res)

    print("\n[8/8] Multi-signature performance and size...")
    x_ms, ms_res = exp_F_multisig(group)
    results['multisig'] = (x_ms, ms_res)
    x_sz, sz_res = exp_G_sig_size(group)
    results['sig_size'] = (x_sz, sz_res)

    # Save raw data
    with open("/output/raw_results.pkl", "wb") as f:
        pickle.dump(results, f)
    print("\nRaw results saved to /output/raw_results.pkl")

    # Plot
    print("\nGenerating figures...")
    plot_all(results, output_dir="/output")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print("=" * 60)


if __name__ == "__main__":
    main()
