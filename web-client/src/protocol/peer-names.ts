// How a name reads, and what tells two people apart: a port of
// LocalPackages/ConnectionPool/Sources/Models/PeerNames.swift for a remote pool, where a person's ID is
// their key. Anyone can pick any name, so whoever shows one that reads like someone else's also shows
// the start of their key. The table is the app's, generated from its source.

const LOOKALIKE_PAIRS: readonly (readonly [string, string])[] = [
  ['а', 'a'], ['в', 'b'], ['е', 'e'], ['ё', 'e'], ['к', 'k'], ['м', 'm'], ['н', 'h'], ['о', 'o'], ['р', 'p'], ['с', 'c'], ['т', 't'], ['у', 'y'],
  ['х', 'x'], ['ѕ', 's'], ['і', 'i'], ['ї', 'i'], ['ј', 'j'], ['һ', 'h'], ['ԁ', 'd'], ['ԛ', 'q'], ['ԝ', 'w'], ['α', 'a'], ['β', 'b'], ['ε', 'e'],
  ['ι', 'i'], ['κ', 'k'], ['ν', 'v'], ['ο', 'o'], ['ρ', 'p'], ['τ', 't'], ['υ', 'u'], ['χ', 'x'], ['ı', 'i'], ['ł', 'l'], ['đ', 'd'], ['ħ', 'h'],
  ['ø', 'o'], ['ŧ', 't'], ['ƀ', 'b'], ['ɑ', 'a'], ['ɡ', 'g'], ['ɩ', 'i'], ['ɵ', 'o'], ['ᴀ', 'a'], ['ʙ', 'b'], ['ᴄ', 'c'], ['ᴅ', 'd'], ['ᴇ', 'e'],
  ['ꜰ', 'f'], ['ɢ', 'g'], ['ʜ', 'h'], ['ɪ', 'i'], ['ᴊ', 'j'], ['ᴋ', 'k'], ['ʟ', 'l'], ['ᴍ', 'm'], ['ɴ', 'n'], ['ᴏ', 'o'], ['ᴘ', 'p'], ['ʀ', 'r'],
  ['ꜱ', 's'], ['ᴛ', 't'], ['ᴜ', 'u'], ['ᴠ', 'v'], ['ᴡ', 'w'], ['ʏ', 'y'], ['ᴢ', 'z'], ['\u{13A0}', 'd'], ['\u{13A1}', 'r'], ['\u{13A2}', 't'], ['\u{13A5}', 'i'], ['\u{13A9}', 'y'],
  ['\u{13AA}', 'a'], ['\u{13AB}', 'j'], ['\u{13AC}', 'e'], ['\u{13B3}', 'w'], ['\u{13B7}', 'm'], ['\u{13BB}', 'h'], ['\u{13BD}', 'y'], ['\u{13C0}', 'g'], ['\u{13C2}', 'h'], ['\u{13C3}', 'z'], ['\u{13CF}', 'b'], ['\u{13D2}', 'r'],
  ['\u{13D4}', 'w'], ['\u{13D5}', 's'], ['\u{13D9}', 'v'], ['\u{13DA}', 's'], ['\u{13DE}', 'l'], ['\u{13DF}', 'c'], ['\u{13E2}', 'p'], ['\u{13E6}', 'k'], ['\u{13F3}', 'g'], ['\u{13F4}', 'b'], ['\u{A4D0}', 'b'], ['\u{A4D1}', 'p'],
  ['\u{A4D2}', 'd'], ['\u{A4D3}', 'd'], ['\u{A4D4}', 't'], ['\u{A4D6}', 'g'], ['\u{A4D7}', 'k'], ['\u{A4D9}', 'j'], ['\u{A4DA}', 'c'], ['\u{A4DC}', 'z'], ['\u{A4DD}', 'f'], ['\u{A4DF}', 'm'], ['\u{A4E0}', 'n'], ['\u{A4E1}', 'l'],
  ['\u{A4E2}', 's'], ['\u{A4E3}', 'r'], ['\u{A4E6}', 'v'], ['\u{A4E7}', 'h'], ['\u{A4EA}', 'w'], ['\u{A4EB}', 'x'], ['\u{A4EC}', 'y'], ['\u{A4EE}', 'a'], ['\u{A4F0}', 'e'], ['\u{A4F2}', 'i'], ['\u{A4F3}', 'o'], ['\u{A4F4}', 'u'],
];

const LOOKALIKES: ReadonlyMap<string, string> = (() => {
  const table = new Map<string, string>();
  for (const [letter, reads] of LOOKALIKE_PAIRS) {
    table.set(letter, reads);
    for (const form of [letter.toLowerCase(), letter.toUpperCase()]) {
      if (Array.from(form).length === 1) table.set(form, reads);
    }
  }
  return table;
})();

/** What reads alike among the Latin letters and digits themselves. */
const ONE_ANOTHER: ReadonlyMap<string, string> = new Map([['l', 'i'], ['1', 'i'], ['|', 'i'], ['0', 'o']]);
const BLANKS = /[\u2800\u3164\uFFA0\u115F\u1160\uFFFC]/gu;
const MAX_FOLDED_CHARS = 1024;
const SHOWN_KEY_LENGTH = 8;

/** What a name reads as. Case, accents, width, spacing, invisible characters and lookalikes make no difference. */
export function foldName(name: string): string {
  const bounded = name.slice(0, MAX_FOLDED_CHARS);
  // What follows a bracket is left out: a name can dress up as another person's name with its tag.
  const plain = bounded.split(/[(（[·#]/u, 1)[0] ?? '';
  const composed = plain.normalize('NFKD').toLowerCase();
  const kept = composed.replace(/[\s\p{Cc}\p{Cf}\p{Mn}\p{Default_Ignorable_Code_Point}]/gu, '').replace(BLANKS, '');
  let out = '';
  for (const char of kept) {
    const latin = LOOKALIKES.get(char) ?? char;
    out += ONE_ANOTHER.get(latin) ?? latin;
  }
  return out;
}

function scriptClass(char: string): 'latin' | 'other' | 'neutral' {
  if (!/\p{L}/u.test(char)) return 'neutral';
  const value = char.codePointAt(0)!;
  const within = (ranges: readonly (readonly [number, number])[]) => ranges.some(([low, high]) => value >= low && value <= high);
  if (within([[0x41, 0x5a], [0x61, 0x7a], [0xaa, 0xaa], [0xba, 0xba], [0xc0, 0x24f], [0x250, 0x2af], [0x1d00, 0x1dbf], [0x1e00, 0x1eff], [0x2c60, 0x2c7f], [0xa720, 0xa7ff], [0xab30, 0xab6f], [0xfb00, 0xfb06]])) return 'latin';
  // Han, kana, bopomofo and Hangul, which are written alongside Latin as a matter of course.
  if (within([[0x1100, 0x11ff], [0x2e80, 0x2fdf], [0x3005, 0x3007], [0x3021, 0x3029], [0x3038, 0x303c], [0x3040, 0x31ff], [0x3400, 0x4dbf], [0x4e00, 0x9fff], [0xa960, 0xa97f], [0xac00, 0xd7ff], [0xf900, 0xfaff], [0xff66, 0xffdc], [0x20000, 0x3ffff]])) return 'neutral';
  return 'other';
}

/** A word mixing Latin with another script: how a name reads like one nobody has picked yet. */
export function mixesScripts(name: string): boolean {
  return name.normalize('NFKC').split(/\s+/u).some((word) => {
    let latin = false;
    let other = false;
    for (const char of word) {
      const kind = scriptClass(char);
      if (kind === 'latin') latin = true;
      else if (kind === 'other') other = true;
    }
    return latin && other;
  });
}

/** Who has been seen under what name in this pool. A name someone has left behind stays taken. */
export class PeerNameBook {
  private readonly holders = new Map<string, Set<string>>();

  hold(name: string, id: string): void {
    const folded = foldName(name);
    const ids = this.holders.get(folded) ?? new Set<string>();
    ids.add(id);
    this.holders.set(folded, ids);
  }

  /** The start of their key, if their name needs telling apart. Never for the person using this page. */
  tag(id: string, name: string, localId: string | null): string | null {
    if (id === localId) return null;
    const others = [...(this.holders.get(foldName(name)) ?? [])].filter((holder) => holder !== id);
    return others.length === 0 && !mixesScripts(name) ? null : id.slice(0, SHOWN_KEY_LENGTH);
  }
}

export function shownName(peer: { displayName: string; nameTag?: string | null }): string {
  return peer.nameTag ? `${peer.displayName} (${peer.nameTag})` : peer.displayName;
}
