// SmaC - inscription et connexion (fenêtres popup)
// - "Commencer maintenant" / "S'inscrire maintenant" : formulaire d'inscription
// - "Connexion" : formulaire de connexion
// Les comptes sont gardés dans le navigateur (localStorage). Les mots de passe ne sont
// jamais stockés en clair : ils sont transformés en empreinte (PBKDF2 + sel aléatoire).

document.addEventListener('DOMContentLoaded', function () {
  const CLE_COMPTES = 'smac_comptes';
  const CLE_SESSION = 'smac_session';
  const CLE_ESSAIS = 'smac_essais';
  const MAX_ESSAIS = 5;
  const BLOCAGE_MS = 30000;
  const crypto_ok = !!(window.crypto && window.crypto.subtle);

  // ---------- Stockage ----------
  function lire(stockage, cle, defaut) {
    try { const v = JSON.parse(stockage.getItem(cle)); return v === null ? defaut : v; }
    catch (e) { return defaut; }
  }
  function ecrire(stockage, cle, valeur) {
    try { stockage.setItem(cle, JSON.stringify(valeur)); return true; }
    catch (e) { return false; }
  }

  // ---------- Mots de passe : jamais en clair ----------
  const enHex = function (buf) {
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  };
  const nouveauSel = function () { return enHex(crypto.getRandomValues(new Uint8Array(16))); };
  async function hacher(motDePasse, selHex) {
    const sel = Uint8Array.from(selHex.match(/../g).map(function (h) { return parseInt(h, 16); }));
    const cle = await crypto.subtle.importKey('raw', new TextEncoder().encode(motDePasse), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: sel, iterations: 100000, hash: 'SHA-256' }, cle, 256);
    return enHex(bits);
  }

  // ---------- Fenêtres ----------
  function creerModal(id, contenu) {
    const m = document.createElement('div');
    m.className = 'modal';
    m.id = id;
    m.hidden = true;
    m.innerHTML = '<div class="modal-fond" data-fermer></div>' +
      '<div class="form-container" role="dialog" aria-modal="true">' +
      '<button class="modal-fermer" type="button" aria-label="Fermer" data-fermer>&times;</button>' +
      contenu + '</div>';
    document.body.appendChild(m);
    m.addEventListener('click', function (e) { if (e.target.closest('[data-fermer]')) fermer(); });
    return m;
  }

  let boutonOuvrant = null;
  function ouvrir(modal, idFocus) {
    document.querySelectorAll('.modal').forEach(function (m) { m.hidden = true; });
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    const cible = document.getElementById(idFocus);
    if (cible) cible.focus();
  }
  function fermer() {
    document.querySelectorAll('.modal').forEach(function (m) { m.hidden = true; });
    document.body.style.overflow = '';
    if (boutonOuvrant) boutonOuvrant.focus();
  }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') fermer(); });

  const erreur = function (id, message) { document.getElementById(id).textContent = message; };
  const effacer = function (ids) { ids.forEach(function (id) { erreur(id, ''); }); };

  // ---------- Fenêtre d'inscription ----------
  const modalInscription = creerModal('modalInscription', `
    <form id="LeFormulaire" novalidate>
      <h2>Enrollment form</h2>
      <p class="modal-intro">This form aims to help the user his enrollment to the platform so that he gets known for the next login !</p>
      <div class="champ"><label for="nom">Name:</label>
        <input class="input-field" id="nom" type="text" placeholder="name" autocomplete="given-name">
        <span class="error-column" id="nomError"></span></div>
      <div class="champ"><label for="surname">Surname:</label>
        <input class="input-field" id="surname" type="text" placeholder="surname" autocomplete="family-name"></div>
      <div class="champ"><label for="email">Email:</label>
        <input class="input-field" id="email" type="email" placeholder="@gmail.com" autocomplete="email">
        <span class="error-column" id="emailError"></span></div>
      <div class="champ"><label for="age">Age:</label>
        <input class="input-field" id="age" type="number" placeholder="e.g : 28">
        <span class="error-column" id="ageError"></span></div>
      <div class="champ"><label for="motDePasse">Password:</label>
        <input class="input-field" id="motDePasse" type="password" placeholder="password" autocomplete="new-password">
        <span class="error-column" id="motDePasseError"></span></div>
      <div class="champ"><label for="ReecrirMotDePasse">Re-enter password:</label>
        <input class="input-field" id="ReecrirMotDePasse" type="password" placeholder="Confirm password" autocomplete="new-password">
        <span class="error-column" id="ReecrirMotDePasseError"></span></div>
      <input class="subscribe-btn" type="submit" value="Subscribe">
      <p class="modal-bas">Déjà un compte ? <button type="button" class="lien" data-connexion>Se connecter</button></p>
    </form>
    <div class="succes" id="succes" hidden>
      <h2 id="succesTitre"></h2>
      <p id="succesTexte"></p>
      <button class="subscribe-btn" type="button" id="succesConnexion" data-connexion>Se connecter</button>
      <button class="subscribe-btn" type="button" id="succesFermer" data-fermer>Fermer</button>
    </div>`);

  const formInscription = document.getElementById('LeFormulaire');
  const succes = document.getElementById('succes');
  const champsInscription = ['nomError', 'emailError', 'ageError', 'motDePasseError', 'ReecrirMotDePasseError'];

  function afficherSucces(titre, texte, boutonConnexion) {
    document.getElementById('succesTitre').textContent = titre;
    document.getElementById('succesTexte').textContent = texte;
    document.getElementById('succesConnexion').hidden = !boutonConnexion;
    formInscription.hidden = true;
    succes.hidden = false;
  }

  function ouvrirInscription(e) {
    if (e) boutonOuvrant = e.currentTarget;
    formInscription.reset();
    effacer(champsInscription);
    const user = utilisateur();
    if (user) {
      afficherSucces('Vous êtes connecté', 'Vous êtes déjà connecté en tant que ' + user.nom + '.', false);
      ouvrir(modalInscription, 'succesFermer');
    } else {
      formInscription.hidden = false;
      succes.hidden = true;
      ouvrir(modalInscription, 'nom');
    }
  }

  formInscription.addEventListener('submit', async function (event) {
    event.preventDefault();
    effacer(champsInscription);

    const nom = document.getElementById('nom').value.trim();
    const surname = document.getElementById('surname').value.trim();
    const email = document.getElementById('email').value.trim().toLowerCase();
    const age = document.getElementById('age').value.trim();
    const password = document.getElementById('motDePasse').value;
    const confirmation = document.getElementById('ReecrirMotDePasse').value;
    let valide = true;

    if (!nom) { erreur('nomError', '* Nom obligatoire.'); valide = false; }
    if (!email) { erreur('emailError', '* E-mail obligatoire.'); valide = false; }
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { erreur('emailError', '* Adresse e-mail invalide.'); valide = false; }
    if (age && (Number(age) < 1 || Number(age) > 120)) { erreur('ageError', '* Âge invalide.'); valide = false; }
    if (!password) { erreur('motDePasseError', '* Mot de passe obligatoire.'); valide = false; }
    else if (password.length < 6) { erreur('motDePasseError', '* 6 caractères minimum.'); valide = false; }
    if (!confirmation) { erreur('ReecrirMotDePasseError', '* Confirmation obligatoire.'); valide = false; }
    else if (confirmation !== password) { erreur('ReecrirMotDePasseError', '* Mots de passe différents.'); valide = false; }
    if (!valide) return;

    if (!crypto_ok) { erreur('motDePasseError', '* Navigateur non compatible (HTTPS requis).'); return; }

    const comptes = lire(localStorage, CLE_COMPTES, []);
    if (comptes.some(function (c) { return c.email === email; })) {
      erreur('emailError', '* Cet e-mail est déjà utilisé.');
      return;
    }

    const sel = nouveauSel();
    comptes.push({ nom: nom, surname: surname, email: email, age: age, sel: sel,
      hash: await hacher(password, sel), cree: new Date().toISOString() });
    if (!ecrire(localStorage, CLE_COMPTES, comptes)) {
      erreur('emailError', '* Impossible d\'enregistrer (stockage bloqué).');
      return;
    }
    formInscription.reset();
    modalInscription.dataset.email = email;
    afficherSucces('✅ Inscription réussie !', 'Bienvenue sur SmaC, ' + nom + ' ! Vous pouvez maintenant vous connecter.', true);
  });

  // ---------- Fenêtre de connexion ----------
  const modalConnexion = creerModal('modalConnexion', `
    <form id="FormConnexion" novalidate>
      <h2>Connexion</h2>
      <p class="modal-intro">Connectez-vous avec l'e-mail et le mot de passe de votre inscription.</p>
      <div class="champ"><label for="connEmail">Email:</label>
        <input class="input-field" id="connEmail" type="email" placeholder="@gmail.com" autocomplete="username">
        <span class="error-column" id="connEmailError"></span></div>
      <div class="champ"><label for="connMotDePasse">Password:</label>
        <input class="input-field" id="connMotDePasse" type="password" placeholder="password" autocomplete="current-password">
        <span class="error-column" id="connMotDePasseError"></span></div>
      <label class="afficher"><input type="checkbox" id="afficherMdp"> Afficher le mot de passe</label>
      <span class="error-column" id="connGlobalError"></span>
      <input class="subscribe-btn" type="submit" value="Se connecter">
      <p class="modal-bas">Pas encore de compte ? <button type="button" class="lien" data-inscription>S'inscrire</button></p>
    </form>`);

  const formConnexion = document.getElementById('FormConnexion');
  const champsConnexion = ['connEmailError', 'connMotDePasseError', 'connGlobalError'];

  function ouvrirConnexion(emailPrerempli) {
    formConnexion.reset();
    effacer(champsConnexion);
    document.getElementById('connMotDePasse').type = 'password';
    if (emailPrerempli) document.getElementById('connEmail').value = emailPrerempli;
    ouvrir(modalConnexion, emailPrerempli ? 'connMotDePasse' : 'connEmail');
  }

  document.getElementById('afficherMdp').addEventListener('change', function (e) {
    document.getElementById('connMotDePasse').type = e.target.checked ? 'text' : 'password';
  });

  // Passer d'une fenêtre à l'autre
  modalInscription.addEventListener('click', function (e) {
    if (e.target.closest('[data-connexion]')) ouvrirConnexion(modalInscription.dataset.email || '');
  });
  modalConnexion.addEventListener('click', function (e) {
    if (e.target.closest('[data-inscription]')) ouvrirInscription();
  });

  formConnexion.addEventListener('submit', async function (event) {
    event.preventDefault();
    effacer(champsConnexion);

    const email = document.getElementById('connEmail').value.trim().toLowerCase();
    const password = document.getElementById('connMotDePasse').value;
    let valide = true;
    if (!email) { erreur('connEmailError', '* E-mail obligatoire.'); valide = false; }
    if (!password) { erreur('connMotDePasseError', '* Mot de passe obligatoire.'); valide = false; }
    if (!valide) return;
    if (!crypto_ok) { erreur('connGlobalError', 'Navigateur non compatible (HTTPS requis).'); return; }

    // Protection : trop d'essais ratés = blocage de 30 secondes
    let essais = lire(localStorage, CLE_ESSAIS, { n: 0, jusqu: 0 });
    if (Date.now() < essais.jusqu) {
      erreur('connGlobalError', 'Trop d\'essais. Réessayez dans ' + Math.ceil((essais.jusqu - Date.now()) / 1000) + ' secondes.');
      return;
    }

    const compte = lire(localStorage, CLE_COMPTES, []).find(function (c) { return c.email === email; });
    const empreinte = await hacher(password, compte ? compte.sel : nouveauSel());

    if (!compte || empreinte !== compte.hash) {
      essais.n += 1;
      if (essais.n >= MAX_ESSAIS) { essais = { n: 0, jusqu: Date.now() + BLOCAGE_MS }; }
      ecrire(localStorage, CLE_ESSAIS, essais);
      // Même message dans les deux cas : on ne révèle pas si l'e-mail existe
      erreur('connGlobalError', 'E-mail ou mot de passe incorrect.');
      return;
    }

    ecrire(localStorage, CLE_ESSAIS, { n: 0, jusqu: 0 });
    ecrire(sessionStorage, CLE_SESSION, compte.email); // la session se termine à la fermeture du navigateur
    formConnexion.reset();
    fermer();
    majEntete();
  });

  // ---------- Session et en-tête ----------
  function utilisateur() {
    const email = lire(sessionStorage, CLE_SESSION, null);
    if (!email) return null;
    return lire(localStorage, CLE_COMPTES, []).find(function (c) { return c.email === email; }) || null;
  }

  // Chaque bouton Connexion est placé dans un bloc, pour y ajouter "Bonjour ..."
  document.querySelectorAll('button.connexion').forEach(function (bouton) {
    const bloc = document.createElement('div');
    bloc.className = 'compte';
    bouton.parentNode.insertBefore(bloc, bouton);
    bloc.appendChild(bouton);
    bouton.addEventListener('click', function (e) {
      if (utilisateur()) {
        sessionStorage.removeItem(CLE_SESSION);
        majEntete();
      } else {
        boutonOuvrant = e.currentTarget;
        ouvrirConnexion('');
      }
    });
  });

  function majEntete() {
    const user = utilisateur();
    document.querySelectorAll('.compte').forEach(function (bloc) {
      const ancien = bloc.querySelector('.salutation');
      if (ancien) ancien.remove();
      const bouton = bloc.querySelector('button.connexion');
      if (user) {
        const salut = document.createElement('span');
        salut.className = 'salutation';
        salut.textContent = 'Bonjour, ' + user.nom;
        bloc.insertBefore(salut, bouton);
        bouton.textContent = 'Déconnexion';
      } else {
        bouton.textContent = 'Connexion';
      }
    });
  }
  majEntete();

  // Boutons qui ouvrent l'inscription
  document.querySelectorAll('button.commencer, button.inscription').forEach(function (bouton) {
    bouton.addEventListener('click', ouvrirInscription);
  });
});
