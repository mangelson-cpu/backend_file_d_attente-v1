import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

serve(async (req) => {
  try {
    // Créer le client admin avec la clé service_role
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL") ?? "http://localhost:8000",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyAgCiAgICAicm9sZSI6ICJzZXJ2aWNlX3JvbGUiLAogICAgImlzcyI6ICJzdXBhYmFzZS1kZW1vIiwKICAgICJpYXQiOiAxNjQxNzY5MjAwLAogICAgImV4cCI6IDE3OTk1MzU2MDAKfQ.DaYlNEoUrrEn2Ig7tqibS-PHK5vgusbcbo7X36XVt4Q",
    );

    // Récupérer le token de l'utilisateur connecté
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Non autorisé" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Vérifier l'utilisateur connecté
    const token = authHeader.replace("Bearer ", "");
    const {
      data: { user: caller },
      error: userError,
    } = await supabaseAdmin.auth.getUser(token);

    if (userError || !caller) {
      return new Response(JSON.stringify({ error: "Utilisateur non trouvé" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Récupérer le profil de l'utilisateur connecté
    const { data: callerProfile, error: profileError } = await supabaseAdmin
      .from("user")
      .select("role, agence_id")
      .eq("id", caller.id)
      .single();

    if (profileError || !callerProfile) {
      return new Response(JSON.stringify({ error: "Profil non trouvé" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Récupérer les données du nouvel utilisateur
    const { email, password, nom_user, role, agence_id } = await req.json();

    // VALIDATION DES DROITS
    // Super_admin peut tout créer
    if (callerProfile.role === "super_admin") {
      // Pas de restrictions supplémentaires
    }
    // Admin ne peut créer que des users dans sa propre agence
    else if (callerProfile.role === "admin") {
      if (role !== "user") {
        return new Response(
          JSON.stringify({
            error:
              "Les admins ne peuvent créer que des utilisateurs (role: user)",
          }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        );
      }
      if (agence_id !== callerProfile.agence_id) {
        return new Response(
          JSON.stringify({
            error:
              "Les admins ne peuvent créer des utilisateurs que dans leur propre agence",
          }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        );
      }
    }
    // User ne peut pas créer
    else {
      return new Response(
        JSON.stringify({
          error: "Les utilisateurs ne peuvent pas créer de comptes",
        }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    }

    // Créer l'utilisateur dans Auth
    const { data: newUser, error: createError } =
      await supabaseAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: {
          nom_user,
          role,
          agence_id,
        },
        app_metadata: {
          role, // Pour le JWT
        },
      });

    if (createError) {
      return new Response(JSON.stringify({ error: createError.message }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Le trigger handle_new_user créera automatiquement l'entrée dans public.user

    return new Response(
      JSON.stringify({
        success: true,
        message: "Utilisateur créé avec succès",
        user: {
          id: newUser.user.id,
          email: newUser.user.email,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
