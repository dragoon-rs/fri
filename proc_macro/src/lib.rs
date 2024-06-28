use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_quote, spanned::Spanned, Ident, ItemStruct};

/// Derives an impl of [`ark_serialize::CanonicalSerialize`] when all the fields implement it. Only supports structs.
/// The type bounds are inferred based on the type of the fields instead of the type parameters.
#[proc_macro_derive(CanonicalSerializeAlt)]
pub fn derive_canonical_serialize(input: TokenStream) -> TokenStream {
    let mut st: ItemStruct = match syn::parse(input) {
        Ok(st) => st,
        Err(mut err) => {
            err.combine(syn::Error::new(
                err.span(),
                "`CanonicalSerializeAlt` currently only supports struct",
            ));
            return err.into_compile_error().into();
        }
    };

    let mut where_clause = st.generics.make_where_clause().clone();
    let (impl_generics, ty_generics, _) = st.generics.split_for_impl();

    let mut fields_serialize = Vec::with_capacity(st.fields.len());
    let mut fields_size = Vec::with_capacity(st.fields.len());
    for (i, field) in st.fields.iter().enumerate() {
        let ident = field
            .ident
            .as_ref()
            .map(|ident| quote! { #ident })
            .unwrap_or_else(|| quote! { #i });
        fields_serialize.push(quote! { ark_serialize::CanonicalSerialize::serialize_with_mode(&self.#ident, &mut writer, compress)?; });
        fields_size.push(
            quote! { ark_serialize::CanonicalSerialize::serialized_size(&self.#ident, compress) },
        );

        let ty = &field.ty;
        where_clause
            .predicates
            .push(parse_quote! { #ty: ark_serialize::CanonicalSerialize });
    }

    let ident = st.ident;
    quote! {
        #[automatically_derived]
        impl #impl_generics ark_serialize::CanonicalSerialize for #ident #ty_generics #where_clause {
            fn serialize_with_mode<W: ark_serialize::Write>(
                &self,
                mut writer: W,
                compress: ark_serialize::Compress,
            ) -> Result<(), ark_serialize::SerializationError> {
                #(#fields_serialize)*
                Ok(())
            }
            fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
                #(#fields_size + )* 0
            }
        }
    }.into()
}

/// Derives an impl of [`ark_serialize::Valid`] and [`ark_serialize::CanonicalDeserialize`] when all the fields
/// implement it. Only supports structs.
/// The type bounds are inferred based on the type of the fields instead of the type parameters.
#[proc_macro_derive(CanonicalDeserializeAlt)]
pub fn derive_canonical_deserialize(input: TokenStream) -> TokenStream {
    let mut st: ItemStruct = match syn::parse(input) {
        Ok(st) => st,
        Err(mut err) => {
            err.combine(syn::Error::new(
                err.span(),
                "`CanonicalDeserializeAlt` currently only supports struct",
            ));
            return err.into_compile_error().into();
        }
    };

    let valid_impl = derive_valid(&mut st);
    let mut where_clause = st.generics.make_where_clause().clone();
    let (impl_generics, ty_generics, _) = st.generics.split_for_impl();

    let mut fields_idents = Vec::with_capacity(st.fields.len());
    let mut fields_deserialize = Vec::with_capacity(st.fields.len());
    for (i, field) in st.fields.iter().enumerate() {
        let ident = field
            .ident
            .as_ref()
            .map(|ident| quote! { #ident })
            .unwrap_or_else(|| Ident::new(&format!("__{i}"), field.span()).to_token_stream());

        fields_deserialize.push(quote! { let #ident = ark_serialize::CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?; });
        fields_idents.push(ident);

        let ty = &field.ty;
        where_clause
            .predicates
            .push(parse_quote! { #ty: ark_serialize::CanonicalDeserialize });
    }

    let ident = st.ident;
    let instanciate = if st.fields.iter().any(|f| f.ident.is_none()) {
        quote! { Self(#(#fields_idents,)*) }
    } else {
        quote! { Self { #(#fields_idents,)* } }
    };

    quote! {
        #valid_impl
        #[automatically_derived]
        impl #impl_generics ark_serialize::CanonicalDeserialize for #ident #ty_generics #where_clause {
            fn deserialize_with_mode<R: ark_serialize::Read>(
                mut reader: R,
                compress: ark_serialize::Compress,
                validate: ark_serialize::Validate,
            ) -> Result<Self, ark_serialize::SerializationError> {
                #(#fields_deserialize)*
                Ok(#instanciate)
            }
        }
    }.into()
}

fn derive_valid(input: &mut ItemStruct) -> proc_macro2::TokenStream {
    let mut where_clause = input.generics.make_where_clause().clone();
    let (impl_generics, ty_generics, _) = input.generics.split_for_impl();

    let mut fields_check = Vec::with_capacity(input.fields.len());
    for (i, field) in input.fields.iter().enumerate() {
        let ident = field
            .ident
            .as_ref()
            .map(|ident| quote! { #ident })
            .unwrap_or_else(|| quote! { #i });
        fields_check.push(quote! { ark_serialize::Valid::check(&self.#ident)?; });

        let ty = &field.ty;
        where_clause
            .predicates
            .push(parse_quote! { #ty: ark_serialize::Valid });
    }

    let ident = &input.ident;
    quote! {
        #[automatically_derived]
        impl #impl_generics ark_serialize::Valid for #ident #ty_generics #where_clause {
            fn check(
                &self,
            ) -> Result<(), ark_serialize::SerializationError> {
                #(#fields_check)*
                Ok(())
            }
        }
    }
}
