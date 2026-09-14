//! The in-application guide.
//!
//! Written for someone who has never used an encrypted vault. Plain words,
//! short sentences, and the limitations stated as plainly as the features:
//! a person deciding what to trust this with needs both.
//!
//! Kept as data rather than inline layout so the text can be reviewed and
//! edited without reading any interface code.

/// A topic: a heading, then paragraphs.
pub struct Topic {
    pub title: &'static str,
    pub body: &'static [&'static str],
}

pub const TOPICS: &[Topic] = &[
    Topic {
        title: "What this program does",
        body: &[
            "A vault is a single file that holds your files in encrypted form. Nobody can \
             read what is inside it without your password, and the file names, sizes and \
             dates are encrypted too, so the vault does not even reveal what sort of things \
             it holds.",
            "You can also set a deadman switch. If you stop checking in for a period you \
             choose, the vault destroys its own key, and everything inside becomes \
             permanently unreadable. This is off unless you turn it on.",
            "Your original files are not moved or changed when you add them to a vault. A \
             copy goes in. If you want the original gone afterwards, you delete it yourself.",
        ],
    },
    Topic {
        title: "Before you trust a vault: where your file has been",
        body: &[
            "This matters more than anything else on this list, and it is the one thing a \
             vault cannot fix for you.",
            "A vault protects what is inside it. It says nothing about where that file has \
             been. Every file you put in one existed somewhere first, on an ordinary \
             unencrypted disk.",
            "Deleting the original afterwards does not remove it. Deleting takes the name \
             off a list and leaves the contents sitting on the disk, where free recovery \
             programs will find them. Emptying the recycle bin does not change that.",
            "It is worse than the one file. Editors quietly save spare copies while you \
             work. Your computer keeps little preview pictures and a search index of what is \
             inside your documents. Windows and Mac take automatic system snapshots without \
             asking. Cloud folders keep their own copies. Solid state drives keep spare \
             space that no program can reach at all.",
            "So what should you do? Turn on full-disk encryption and leave it on: BitLocker \
             on Windows, FileVault on a Mac. Use a real passphrase rather than a short PIN. \
             Then every one of those leftovers is encrypted too, and somebody with your \
             switched-off computer has to break that before any of it matters.",
            "Shut your computer down rather than leaving it asleep. A sleeping computer is \
             still holding the key.",
            "For genuinely sensitive material, go further: create the file on a USB drive \
             from the start and make the vault there, so your main disk never sees it. The \
             file docs/BEFORE-THE-VAULT.txt explains the rest, including which popular \
             remedies do not work.",
        ],
    },
    Topic {
        title: "Creating your first vault",
        body: &[
            "Go to the Vault section and press Create. Choose where to save the vault file \
             and give it a name. Then choose a password.",
            "There is no way to reset this password. Nobody can recover it for you, and \
             neither can we: that is the point of the design, not a missing feature. If the \
             password is lost and you have not set up key protection, everything in the \
             vault is gone.",
            "Use a long password you will not forget, or store it in a password manager.",
        ],
    },
    Topic {
        title: "Adding files",
        body: &[
            "In the Vault section, press Add file and pick a file. Enter your password. The \
             file is compressed, encrypted and stored.",
            "Add as many as you like. The list under Contents shows what is inside once the \
             vault is unlocked.",
        ],
    },
    Topic {
        title: "Getting your files back",
        body: &[
            "Press Unlock and enter your password. The Contents list then shows what is \
             stored. Press Extract beside a file, or Extract all, and choose a folder.",
            "Extracting writes a decrypted copy into that folder. The vault keeps its own \
             copy, so extracting does not empty it.",
            "Until you unlock, the list is empty and says so. That is normal: the names are \
             encrypted along with everything else, so there is nothing to show yet.",
        ],
    },
    Topic {
        title: "Why a password alone may not be enough",
        body: &[
            "If somebody takes the drive out of your computer and connects it elsewhere, \
             they can copy your vault and try passwords on it for as long as they like, on \
             their own machine, with nothing to stop them. Your deadman switch cannot help: \
             they are not running this program.",
            "Key protection fixes that. It splits the key needed to open your vault into \
             three pieces, and any two of them will open it. One piece is your password. The \
             other two are small files called tokens.",
            "Someone who steals the drive gets the vault and, at most, your password. That is \
             one piece. They need two.",
        ],
    },
    Topic {
        title: "Setting up key protection",
        body: &[
            "Go to Key protection and press Protect. You will be asked where to save two \
             token files. Then enter your password.",
            "This is quick even for a very large vault, because only a tiny piece of the file \
             changes. Your stored files are not re-encrypted.",
            "Afterwards your password on its own will no longer open the vault, on this \
             computer or any other.",
        ],
    },
    Topic {
        title: "Where to keep the two tokens",
        body: &[
            "Not on the same drive as the vault. If a thief takes the drive and the tokens \
             are on it, they have everything, and you have gained nothing at all.",
            "Put the first token on a USB stick you keep somewhere else. Put the second \
             somewhere different again: another building, a safe, or with a person you trust.",
            "Do not keep both tokens together. Any two pieces open the vault, so whoever has \
             both tokens can open it without ever knowing your password.",
            "Keep them safe rather than secret-and-lost. Two tokens plus your password is \
             three pieces, so losing any one of them is survivable. Losing two is not.",
        ],
    },
    Topic {
        title: "Opening a protected vault",
        body: &[
            "Each time you use the program, press Add token in the Key protection section and \
             point it at one of your token files. Then use your password as normal.",
            "If a file is not a token, the program will say so straight away and ignore it. \
             Attaching the wrong file by mistake does no harm.",
            "If you have forgotten your password, tick Password lost and attach both tokens \
             instead. That is what the second token is for.",
        ],
    },
    Topic {
        title: "What protects you from someone at your computer",
        body: &[
            "This is worth being blunt about, because it is easy to assume the deadman \
             switch is the answer and it is not.",
            "Somebody who has your computer, in person or remotely, can simply close the \
             watcher. Nothing can stop them. A hidden background program is visible in the \
             task list within a minute. Refusing to close without a password is defeated by \
             ending the task. Two programs restarting each other is how malware behaves and \
             is how your antivirus will treat it. On a machine somebody else controls, they \
             win that fight.",
            "So the deadline is not what defends you there. KEY PROTECTION is. An attacker \
             who stops the watcher buys themselves unlimited time to attack your vault, and \
             against a split key unlimited time is worth nothing: they hold one piece and \
             need two. A thousand years of guessing your password still leaves them a piece \
             short.",
            "What the deadman switch is genuinely for is you not coming back. Illness, \
             arrest, an accident, a border detention. In those cases nobody closes anything: \
             the machine simply sits there, the deadline passes, and the key is destroyed.",
            "Two things do help against a closed watcher. Stopping it postpones nothing, \
             because elapsed time is measured from recorded timestamps rather than by \
             counting: kill it for a week and the moment it runs again it sees that a week \
             has passed and acts at once. And it cannot be stopped quietly, because the next \
             start records that the previous one ended without shutting down, so you find \
             out on your return.",
        ],
    },
    Topic {
        title: "Checking in, and what the deadman switch does",
        body: &[
            "The deadman switch is off until you turn it on, and it does nothing to your data \
             unless you also run the background service. Setting it up is safe on its own.",
            "Checking in means pressing Check in and entering your password. It tells the \
             program you are alive, well, and acting freely. Doing so resets the countdown.",
            "Timeout is how long you can go without checking in before the vault is considered \
             abandoned. Three days is a common choice.",
            "Heartbeat is how often you intend to check in. Inside that time your check-in \
             counts fully. After it, the presence score falls steadily until the timeout is \
             reached.",
            "Required confidence is how high that score must stay. Entering your password \
             scores 100. Weaker evidence, such as the computer being switched on, reachable \
             on the network, or having its keyboard used, is capped at 60 in total however \
             much of it there is.",
            "That cap is the reason the setting cannot go below 61. None of that weaker \
             evidence proves anything about you: a burglar sitting at your desk produces \
             every one of those signs, and so does a machine left running in an empty \
             house. A deadline that they could hold open would not be a deadman switch, it \
             would be a switch that notices whether the computer is on.",
        ],
    },
    Topic {
        title: "Turning the deadman switch on for real",
        body: &[
            "Saving a policy is not the same as arming it. This window shows the countdown \
             but never acts on it. Nothing is destroyed until a separate background program \
             is running and has been given permission.",
            "That separation is deliberate. A checkbox should not be able to start something \
             that erases your files, and a program started by this window would stop the \
             moment you closed it, leaving you believing you were protected when you were \
             not.",
            "First, run a dry run from the Destruction section and read it. Then run the \
             service without permission to destroy, and watch it reach ARMED and stop. Only \
             once both of those hold no surprises should you add the permission.",
            "The Deadman section shows the exact command and will copy it for you. To have \
             it survive a restart, use `zt service unit` to produce a definition for your \
             operating system, and hand that to whoever administers the machine.",
        ],
    },
    Topic {
        title: "Destroying a vault on purpose",
        body: &[
            "Panic lock is safe. It clears anything held in memory and leaves your files \
             completely untouched. Use it whenever you want.",
            "Dry run is also safe. It lists exactly what destruction would do and changes \
             nothing at all. Do this once before trusting the deadman switch, so nothing is a \
             surprise later.",
            "Panic destroy is permanent. It overwrites the key, and afterwards no password, \
             no token and no backup of the key will open that vault again.",
            "Destroying needs the same pieces as opening. If your vault is protected, you must \
             attach a token as well as entering your password. That is deliberate: somebody \
             who cannot read your vault should not be able to destroy it either.",
        ],
    },
    Topic {
        title: "What the Records section is for",
        body: &[
            "Records checks the program's own logs, not your files. It can tell you whether \
             anyone has edited, deleted or reordered the history of what happened to this \
             vault.",
            "Verify, in the sidebar, is the different one: it decrypts every stored file and \
             checks it against its fingerprint, to find damage or tampering in the data \
             itself. It can be slow on a large vault.",
        ],
    },
    Topic {
        title: "What this program cannot do",
        body: &[
            "It cannot protect a copy you made earlier. If you backed the vault up before \
             destroying it, that backup still opens with your password. Destruction protects \
             the file you destroyed, not copies of it elsewhere.",
            "It cannot protect you from someone who is already inside your computer while the \
             vault is open. At that moment your files are readable by you, and therefore by \
             anything running as you.",
            "It cannot notice if someone with your drive rolls it back to an older state. \
             Detecting that needs hardware support this version does not have.",
            "It cannot recover a lost password on an unprotected vault. Nothing can.",
        ],
    },
    Topic {
        title: "A good first hour",
        body: &[
            "Create a practice vault with a file you do not care about. Add it, unlock, \
             extract it, and check the extracted copy opens normally.",
            "Set up key protection on that practice vault. Attach a token and open it again. \
             Then try opening it with the token deliberately absent, and watch it refuse.",
            "Run a dry run, read what it says, then use Panic destroy on the practice vault \
             and read the report.",
            "Once none of that surprises you, make the real one.",
        ],
    },
];
